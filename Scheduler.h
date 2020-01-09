// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#pragma once

constexpr UINT32 PRIORITY_COUNT = 8;

constexpr UINT32 MAX_SCHEDULER_PRIORITY = 7;
constexpr UINT32 MIN_SCHEDULER_PRIORITY = 0;

using TASK_ID = UINT32;
constexpr UINT32 INVALID_TASKID = 0xFFFFFFFF;

#define MAKE_TASKID(priority, id_) (((priority & 0xFF) << 16) | (id_ & 0xFFFF))
#define GET_QUEUE_PRIORITY(taskid_) ((taskid_ & 0xFF0000) >> 16)
#define GET_QUEUE_INDEX(taskid_) (taskid_ & 0xFFFF)

#define MAX_PROCESSOR_COUNT	64

struct STASK_PARAMS
{
	BUFFER paramData;

	template <typename T>
	T read()
	{
		T value;
		paramData.copyTo((PUINT8)&value, sizeof(value));
		return value;
	}

	STASK_PARAMS(BUFFER dataArg) : paramData(dataArg) {}
};

using TASK_HANDLER = void(*)(PVOID context, NTSTATUS result, STASK_PARAMS argv);

enum class TASK_STATUS : UINT8
{
	UNKNOWN,
	SCHEDULED,
	READY,
	RUNNING,
	COMPLETE,
};

struct STASK
{
	LOCAL_STREAM<64> paramStream;
	PVOID context;
	NTSTATUS result;

	TASK_STATUS status;
	TASK_HANDLER handler;

	void AddArg() {}
	template <typename T, typename ... ARGS>
	void AddArg(T&& arg, ARGS&& ... args)
	{
		paramStream.writeBytes((PUINT8)&arg, sizeof(arg));
		AddArg(args ...);
	}

	template <typename ... ARGS>
	STASK(TASK_HANDLER handlerArg, PVOID contextArg, ARGS&& ... params)
	{
		handler = handlerArg;
		context = contextArg;
		result = STATUS_SUCCESS;
		AddArg(params ...);
	}

	STASK() : handler(nullptr), context(nullptr), result(STATUS_SUCCESS)
	{
		paramStream.clear();
	}

	STASK(STASK& other)
	{
		paramStream.clear().writeBytes(other.paramStream.toBuffer());
		context = other.context;
		result = other.result;
		status = other.status;
		handler = other.handler;
	}

	void run()
	{
		ASSERT(handler != nullptr);
		handler(context, result, paramStream.toBuffer());
		handler = nullptr;
	}

	explicit operator bool() { return handler != nullptr; }
};

struct QUEUE_HEAD
{
	LONG read;
	LONG write;
};

struct SCHEDULER_STACK
{
	UINT32 stackSize = 4 * 1024 * 1024;
	PUINT8 startAddress;
	PUINT8 currentAddress;

	UINT32 overflowStackSize = 0;
	PUINT8 overflowStart = nullptr;
	PUINT8 overflowCurrent = nullptr;

	DICTIONARY<TOKENTYPE::NAME_SCHEDULER, SCHEDULER_STACK, 6000, 1000, 2000> dictionary;

	STREAM_BUILDER<USTRING, SCHEDULER_STACK, 64> literals;
	STREAM_BUILDER<INT64, SCHEDULER_STACK, 256> numberHandles;

	STREAM_BUILDER<TOKEN, SCHEDULER_STACK, 256> blobHandles;
	STREAM_BUILDER<UINT8, SCHEDULER_STACK, 16 * 1024> blobStream;

	void clear()
	{
		ClearOverflowHeap(*this);
		currentAddress = startAddress + sizeof(PVOID);

		new (&dictionary) DICTIONARY<TOKENTYPE::NAME_SCHEDULER, SCHEDULER_STACK, 6000, 1000, 2000>();

		new (&literals) STREAM_BUILDER<USTRING, SCHEDULER_STACK, 64>();
		new (&numberHandles) STREAM_BUILDER<INT64, SCHEDULER_STACK, 256>();

		new (&blobHandles) STREAM_BUILDER<TOKEN, SCHEDULER_STACK, 256>();
		new (&blobStream) STREAM_BUILDER<UINT8, SCHEDULER_STACK, 16 * 1024>();
	}
};

constexpr UINT32 MAX_SYSTEM_THREAD = 8;
constexpr UINT32 SYSTEM_SCHEDULER_QUEUE_SIZE = 64;
constexpr UINT32 SYSTEM_SCHEDULER_QUEUE_MASK = SYSTEM_SCHEDULER_QUEUE_SIZE - 1;

struct SYSTEM_SCHEDULER;
extern SYSTEM_SCHEDULER* SystemSchedulerPtr;

struct SYSTEM_SCHEDULER
{
	HANDLE threadHandle;
	KEVENT threadEvent;
	KEVENT createEvent;

	KSPIN_LOCK queueLock;

	SCHEDULER_STACK allocHeap[MAX_SYSTEM_THREAD];
	PKTHREAD threadId[MAX_SYSTEM_THREAD];

	LONG read;
	LONG write;

	STASK taskQueue[SYSTEM_SCHEDULER_QUEUE_SIZE];

	SCHEDULER_STACK& GetCurrentStack()
	{
		auto thread = KeGetCurrentThread();
		for (UINT32 i = 0; i < MAX_SYSTEM_THREAD; i++)
		{
			if (threadId[i] == thread)
			{
				return allocHeap[i];
			}
		}
		return NullRef<SCHEDULER_STACK>();
	}

	bool findSystemTask(STASK &nextTask)
	{
		KIRQL oldIrql;
		KeAcquireSpinLock(&queueLock, &oldIrql);

		auto result = false;;

		while (read != write)
		{
			auto& task = taskQueue[read];
			if (task.status == TASK_STATUS::READY)
			{
				RtlCopyMemory(&nextTask, &task, sizeof(STASK));
				task.status = TASK_STATUS::COMPLETE;
				read = (read + 1) & SYSTEM_SCHEDULER_QUEUE_MASK;
				result = true;
				break;
			}
			else DbgBreakPoint();
		}

		KeReleaseSpinLock(&queueLock, oldIrql);

		return result;
	}

	template <typename TASK>
	void runTask(TASK&& task)
	{
		KIRQL oldIrql;
		KeAcquireSpinLock(&queueLock, &oldIrql);

		auto currentIndex = write;
		auto nextIndex = (currentIndex + 1) & SYSTEM_SCHEDULER_QUEUE_MASK;

		if (InterlockedCompareExchange(&write, nextIndex, currentIndex) == currentIndex)
		{
			auto& newTask = taskQueue[currentIndex];
			new (&newTask) STASK(task);
			newTask.status = TASK_STATUS::READY;
		}
		else DbgBreakPoint();

		KeSetEvent(&threadEvent, 0, FALSE);

		KeReleaseSpinLock(&queueLock, oldIrql);
	}

	static VOID SchedulerThread(PVOID context)
	{
		auto index = (UINT32)context;
		auto&& scheduler = *SystemSchedulerPtr;

		scheduler.threadId[index] = KeGetCurrentThread();
		InitializeStack(scheduler.allocHeap[index], 4 * 1024 * 1024, 64 * 1024 * 1024);

		KeSetEvent(&scheduler.createEvent, 0, FALSE);
		while (true)
		{
			KeWaitForSingleObject(&scheduler.threadEvent, Executive, KernelMode, FALSE, NULL);

			STASK task;
			while (scheduler.findSystemTask(task))
			{
				task.handler(task.context, task.result, task.paramStream.toBuffer());
			}
		}
	}

	NTSTATUS initialize()
	{
		auto status = STATUS_SUCCESS;
		do
		{
			for (UINT32 i = 0; i < SYSTEM_SCHEDULER_QUEUE_SIZE; i++)
			{
				new (&taskQueue[i]) STASK();
			}
			KeInitializeEvent(&threadEvent, SynchronizationEvent, FALSE);
			KeInitializeEvent(&createEvent, SynchronizationEvent, FALSE);

			for (UINT32 i = 0; i < MAX_SYSTEM_THREAD; i++)
			{
				status = PsCreateSystemThread(&threadHandle, (ACCESS_MASK)0, NULL, (HANDLE)0, NULL, SchedulerThread, (PVOID)i);
				if (!NT_SUCCESS(status))
					break;

				KeWaitForSingleObject(&createEvent, Executive, KernelMode, FALSE, NULL);

				ZwClose(threadHandle);
			}
			VERIFY_STATUS;
			if (!NT_SUCCESS(status))
				break;
		} while (false);
		return status;
	}
};

extern SYSTEM_SCHEDULER& SystemScheduler();
extern NTSTATUS CreateSystemScheduler();

template<typename T>
void SetCurrentScheduler(SCHEDULER_STACK &stack, T& context);
void ResetCurrentScheduler();
extern SCHEDULER_STACK* GetCurrentScheduler();

template <typename CONTEXT, UINT32 QUEUE_SIZE = 128, UINT32 QUEUE_MASK = 127>
struct SCHEDULER_INFO
{
	struct TASK_QUEUE
	{
		STASK taskQueue[QUEUE_SIZE];
	};

	CONTEXT& context;
	KDPC runHandler;

	SCHEDULER_STACK schedulerStack;

	KSPIN_LOCK queueLock;
	PROCESSOR_NUMBER processor;

	QUEUE_HEAD queueHead[PRIORITY_COUNT];
	TASK_QUEUE taskQueues[PRIORITY_COUNT];

	SCHEDULER_INFO(CONTEXT& contextArg) : context(contextArg) {};

	auto findReadyTask(INT32 lowPriority)
	{
		STASK* taskFound = nullptr;
		for (INT32 i = MAX_SCHEDULER_PRIORITY; i >= lowPriority; i--)
		{
			auto& currentQueue = taskQueues[i];
			auto& currentIndex = queueHead[i];

			while (currentIndex.read != currentIndex.write)
			{
				auto read = currentIndex.read;
				auto& task = currentQueue.taskQueue[read];
				if (task.status == TASK_STATUS::RUNNING)
				{
					task.status = TASK_STATUS::COMPLETE;
					currentIndex.read = (read + 1) & QUEUE_MASK;
				}
				else if (task.status == TASK_STATUS::READY)
				{
					task.status = TASK_STATUS::RUNNING;
					if (task.handler)
					{
						taskFound = &task;
						break;
					}
				}
				else break;
			}

			if (taskFound)
				break;

			if (currentIndex.read != currentIndex.write)
				break;
		}

		return taskFound;
	}

	void runReadyTasks(INT32 lowPriority)
	{
		SetCurrentScheduler(schedulerStack, context);

		while (auto nextTask = findReadyTask(lowPriority))
		{
			nextTask->handler(nextTask->context, nextTask->result, nextTask->paramStream.toBuffer());
		}

		ResetCurrentScheduler();
	}

	static VOID RunDpcScheduler(PKDPC, PVOID context, PVOID, PVOID)
	{
		auto& scheduler = *(SCHEDULER_INFO<CONTEXT>*)context;
		scheduler.runReadyTasks(0);
	}

	bool isRunning()
	{
		return GetCurrentScheduler() == &schedulerStack;
	}

	void runNow(INT32 lowPriority)
	{
		PROCESSOR_NUMBER currentProcessor;
		KeGetCurrentProcessorNumberEx(&currentProcessor);

		if (processor.Number == currentProcessor.Number && isRunning() == false)
		{
			runReadyTasks(lowPriority);
		}
		else DBGBREAK();
	}

	TASK_QUEUE& getTaskQueue(TASK_ID taskId)
	{
		auto priority = GET_QUEUE_PRIORITY(taskId);
		return taskQueues[priority];
	}

	STASK& getTask(TASK_ID taskId)
	{
		auto&& taskStack = getTaskQueue(taskId);
		return taskStack.taskQueue[GET_QUEUE_INDEX(taskId)];
	}

	template <typename TASK>
	TASK_ID queueTask(UINT32 priority, TASK&& task)
	{
		auto& taskQueue = taskQueues[priority];
		auto& header = queueHead[priority];

		UINT32 taskId;
		while (true)
		{
			auto currentIndex = header.write;
			auto nextIndex = (currentIndex + 1) & QUEUE_MASK;

			ASSERT((LONG)nextIndex != header.read);

			if (InterlockedCompareExchange(&header.write, nextIndex, currentIndex) == currentIndex)
			{
				auto& newTask = taskQueue.taskQueue[currentIndex];
				new (&newTask) STASK(task);
				newTask.status = TASK_STATUS::SCHEDULED;
				taskId = MAKE_TASKID(priority, currentIndex);
				break;
			}
		}

		return taskId;
	}

	template <typename STREAM>
	void addParam(STREAM&& )
	{
	}

	template <typename STREAM, typename T, typename ... ARGS>
	void addParam(STREAM&& stream, T&& arg, ARGS&& ... args)
	{
		stream.writeBytes((PUINT8)&arg, sizeof(arg));
		addParam(stream, args ...);
	}

	template <typename ... ARGS>
	VOID updateTask(TASK_ID taskId, NTSTATUS result = STATUS_SUCCESS, ARGS&& ... args)
	{	
		auto& task = getTask(taskId);
		ASSERT(task.status == TASK_STATUS::SCHEDULED);
		task.status = TASK_STATUS::READY;
		task.result = result;

		addParam(task.paramStream, args ...);

		KeInsertQueueDpc(&runHandler, nullptr, nullptr);
	}

	template <typename TASK>
	void runTask(UINT32 priority, TASK&& task)
	{
		auto taskId = queueTask(priority, task);
		updateTask(taskId, STATUS_SUCCESS);
	}

	NTSTATUS initialize()
	{
		auto status = STATUS_SUCCESS;
		do
		{
			auto processorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
			ASSERT(processorCount < MAX_PROCESSOR_COUNT);

			KeGetProcessorNumberFromIndex(processorCount - 1, &processor);

			KeInitializeDpc(&runHandler, RunDpcScheduler, this);

			KeSetTargetProcessorDpcEx(&runHandler, &processor);
			KeSetImportanceDpc(&runHandler, HighImportance);

			KeInitializeSpinLock(&queueLock);

			for (UINT32 i = 0; i < PRIORITY_COUNT; i++)
			{
				queueHead[i].read = queueHead[i].read = 0;
			}

			for (UINT32 i = 0; i < PRIORITY_COUNT; i++)
			{
				auto& taskQueue = taskQueues[i];
				for (UINT32 j = 0; j < QUEUE_SIZE; j++)
				{
					new (&taskQueue.taskQueue[j]) STASK();
				}
			}
			InitializeStack(schedulerStack, 8 * 1024 * 1024, 0);

		} while (false);
		return status;
	}
};

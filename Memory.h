// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#pragma once

constexpr void* operator new (size_t, void* ptr) { return ptr; }

constexpr ULONG POOL_TAG = 'KATS';

extern PVOID KernelAlloc(UINT32 size);

template <typename T, typename ... Args>
T& KernelAlloc(Args&& ... args)
{
	auto address = (T*)KernelAlloc(sizeof(T));
	new (address) T(args ...);
	return *address;
}

template <typename ST>
void* StackAlloc(UINT32 size)
{
	auto& stackInfo = GetCurrentStack<ST>();
	ASSERT(stackInfo.currentAddress);
	PVOID newAddress = nullptr;
	if ((stackInfo.currentAddress + size) < (stackInfo.startAddress + stackInfo.stackSize))
	{
		auto current = stackInfo.currentAddress;
		newAddress = InterlockedCompareExchangePointer((volatile PVOID*)& stackInfo.currentAddress, (current + size), current);
		ASSERT(newAddress == current);
	}
	else
	{
		ASSERT(stackInfo.overflowStackSize != 0);
		if (stackInfo.overflowStart == nullptr)
		{
			stackInfo.overflowStart = (PUINT8)KernelAlloc(stackInfo.overflowStackSize);
			ASSERT(stackInfo.overflowStart != nullptr);
			stackInfo.overflowCurrent = stackInfo.overflowStart;
		}
		auto current = stackInfo.overflowCurrent;
		if ((stackInfo.overflowCurrent + size) < (stackInfo.overflowStart + stackInfo.overflowStackSize))
		{
			newAddress = InterlockedCompareExchangePointer((volatile PVOID*)& stackInfo.overflowCurrent, current + size, current);
			ASSERT(newAddress == current);
		}
		else DBGBREAK();
	}
	return newAddress;
}

template <typename T, typename ST, typename ... Args>
T& StackAlloc(Args&& ... args)
{
	auto newAddress = (PUINT8)StackAlloc<ST>(sizeof(T));
	new (newAddress) T(args ...);

	return *(T*)newAddress;
}

template <typename ST>
NTSTATUS InitializeStack(ST& stack, UINT32 staticSize, UINT32 dynamicSize)
{
	auto status = STATUS_SUCCESS;
	do
	{
		stack.stackSize = staticSize;
		stack.overflowStackSize = dynamicSize;

		if (stack.startAddress == NULL)
		{
			stack.startAddress = (PUINT8)KernelAlloc(stack.stackSize);
			if (stack.startAddress == nullptr)
			{
				LogError("CreateStack: ExAlloc failed for size: %d", stack.stackSize);
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			*(PVOID*)stack.startAddress = stack.startAddress;
		}
		ASSERT(*(PVOID*)stack.startAddress == stack.startAddress);
		stack.currentAddress = stack.startAddress + sizeof(PVOID);
	} while (false);
	return status;
}

template <typename STACK>
void ClearOverflowHeap(STACK& stack)
{
	if (stack.overflowStackSize > 0 && stack.overflowStart != nullptr)
	{
		stack.overflowStackSize = 0;
		ExFreePoolWithTag(stack.overflowStart, POOL_TAG);
		stack.overflowCurrent = stack.overflowStart = nullptr;
	}
}

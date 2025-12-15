#include <ntifs.h>


extern "C" {
	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DiverName, PDRIVER_INITIALIZE InitializationFunction);
	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAdress,
		PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode,
		PSIZE_T ReturnSize);
	
}


void debug_print(PCSTR text) {
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, text));
}

namespace driver {

	namespace code {
		constexpr ULONG atach = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
		constexpr ULONG allocate = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	}

	struct Request{
		HANDLE process_id;
		PVOID base_adress;
		SIZE_T memory_size;
		ULONG protection;
	};

	NTSTATUS create(PDEVICE_OBJECT device_object, PIRP irp) {
		UNREFERENCED_PARAMETER(device_object); 

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	 }

	NTSTATUS close(PDEVICE_OBJECT device_object, PIRP irp) {
		UNREFERENCED_PARAMETER(device_object);  
		
		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	}

	NTSTATUS allocate_memory(PEPROCESS target, PVOID* base_address, SIZE_T* size, ULONG protection) {
		UNREFERENCED_PARAMETER(protection);
		debug_print("allocate memory called\n");
		NTSTATUS status = STATUS_SUCCESS;
		
		KAPC_STATE apc_state;
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
			"=== PARAMETER DUMP ===\n"));
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
			"Target EPROCESS: 0x%p\n", target));
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
			"BaseAddress pointer: 0x%p\n", base_address));
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
			"Size pointer: 0x%p\n", size));

	
		HANDLE process_handle = NULL;


		KdPrint(("Process handle: 0x%p\n", process_handle));
		if (target == nullptr) {
			debug_print("target null pointer");
			return STATUS_UNSUCCESSFUL;
		}

		debug_print("before kestack prcess\n");
		char buffer[64] = { 0 };
		KeStackAttachProcess(target, &apc_state);

		debug_print("after kestack prcess");

		PVOID local_base_adress = NULL;
		SIZE_T	local_size = *size;

		debug_print("before zwallocate\n");
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
			"Calling ZwAllocateVirtualMemory:\n"));
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
			"  Process: 0x%p\n", NtCurrentProcess()));
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
			"  BaseAddress: 0x%p\n", local_base_adress));
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
			"  Size: 0x%zX\n", local_size));
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
			"  AllocationType: 0x%X (MEM_COMMIT)\n", MEM_COMMIT));
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
			"  Protect: 0x%X\n", protection));

		status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &local_base_adress, 0, &local_size, MEM_COMMIT | MEM_RESERVE, protection);
		if (status != STATUS_SUCCESS) {
			debug_print("error alocating  memory\n");
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Status: 0x%X\n", status));
			KeUnstackDetachProcess(&apc_state);
			ObDereferenceObject(target);
			return status;
		}

		const char *a = "razvan a fost aici xd";
		memcpy(local_base_adress,a,strlen(a) + 1);

		debug_print("after zwallocate\n");
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
			"  BaseAddress: 0x%p\n", local_base_adress));
		


		ZwCreateThreadEx(0, 0, 0, 0);
		memcpy(buffer, local_base_adress, min(sizeof(buffer) - 1, 10));

		KeUnstackDetachProcess(&apc_state);
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "read back from target process:%s\n", buffer));
		

		if (NT_SUCCESS(status)) {
			*base_address = local_base_adress;
			*size = local_size;
		}
		debug_print("memory allocated to process");
		return status;
	}
	NTSTATUS device_control(PDEVICE_OBJECT device_object, PIRP irp) {
		debug_print("in device control");
		UNREFERENCED_PARAMETER(device_object); 

		NTSTATUS status = STATUS_UNSUCCESSFUL;

		
		PIO_STACK_LOCATION stack_irp = IoGetCurrentIrpStackLocation(irp);
		
		auto request = reinterpret_cast<Request*>(irp->AssociatedIrp.SystemBuffer);
		if (stack_irp == nullptr || request == nullptr) {
			debug_print("unbale to get request ot stack_ipr poitner");
			return status;
		}
	
		static PEPROCESS target_process = nullptr;

		const ULONG control_code = stack_irp->Parameters.DeviceIoControl.IoControlCode;
		if (control_code == code::atach) {
			status = PsLookupProcessByProcessId(request->process_id, &target_process);
		 }
		else if (control_code == code::allocate) {
			debug_print("before allocat\n");
			status = allocate_memory(target_process, &request->base_adress, &request->memory_size, request->protection);
		}

		irp->IoStatus.Status = status;
		irp->IoStatus.Information = sizeof(Request);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return status;
	}

}
NTSTATUS driver_main(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path_) {
	UNREFERENCED_PARAMETER(registry_path_);
	_UNICODE_STRING device_name = {};
	RtlInitUnicodeString(&device_name, L"\\Device\\testdriver");
	
	PDEVICE_OBJECT device_object = nullptr;
	NTSTATUS status = IoCreateDevice(
		driver_object,
		0,
		&device_name,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&device_object
	);
	if (status != STATUS_SUCCESS) {
		debug_print("Unable to initalize the device");
		return status;
	}

	UNICODE_STRING symbolic_link = {};
	RtlInitUnicodeString(&symbolic_link, L"\\DOSDevices\\testdriver");
	status = IoCreateSymbolicLink(&symbolic_link, &device_name); 
	if(status != STATUS_SUCCESS){
		debug_print("symbolic link failed");
		return status;
	}
	
	driver_object->MajorFunction[IRP_MJ_CREATE] = driver::create;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = driver::close;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver::device_control;

	ClearFlag(device_object->Flags, DO_DEVICE_INITIALIZING);
	debug_print("symbolic link created to usermode process\n");

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry() {
	debug_print("[*] Starting driver\n");

	_UNICODE_STRING driver_name = {};
	RtlInitUnicodeString(&driver_name, L"\\Driver\\testdriver");
	return IoCreateDriver(&driver_name, &driver_main);

}

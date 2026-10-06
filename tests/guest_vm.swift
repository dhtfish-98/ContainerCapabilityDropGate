import Foundation
import Virtualization

@main
struct CapabilityGuest {
    static func main() async throws {
        guard CommandLine.arguments.count == 3 else {
            fputs("usage: guest_vm KERNEL INITRAMFS\n", stderr)
            exit(64)
        }
        let configuration = VZVirtualMachineConfiguration()
        configuration.cpuCount = 2
        configuration.memorySize = 1024 * 1024 * 1024
        configuration.platform = VZGenericPlatformConfiguration()
        let loader = VZLinuxBootLoader(kernelURL: URL(fileURLWithPath: CommandLine.arguments[1]))
        loader.initialRamdiskURL = URL(fileURLWithPath: CommandLine.arguments[2])
        loader.commandLine = "console=hvc0 rdinit=/bin/sh panic=0"
        configuration.bootLoader = loader
        let serial = VZVirtioConsoleDeviceSerialPortConfiguration()
        serial.attachment = VZFileHandleSerialPortAttachment(
            fileHandleForReading: FileHandle.standardInput,
            fileHandleForWriting: FileHandle.standardOutput
        )
        configuration.serialPorts = [serial]
        try configuration.validate()
        let machine = VZVirtualMachine(configuration: configuration)
        try await machine.start()
        while machine.state != .stopped {
            try await Task.sleep(for: .milliseconds(250))
        }
    }
}

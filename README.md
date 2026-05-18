# 🔍 ReadPE: Portable Executable (PE) Parser

> ReadPE is a lightweight C program built to parse Windows Portable Executable (PE) files directly from disk. Bypassing high-level APIs, it reads DOS/NT headers, resolves Relative Virtual Addresses (RVAs) to physical offsets, and extracts the Import Address Table (IAT).

## 📖 About the Project

This project was developed as a hands-on approach to understanding the underlying architecture of the Windows PE file format. Instead of relying on abstractions like the `ImageHlp` API or built-in dumping tools, ReadPE manually navigates the binary's raw structure. 

It demonstrates proficiency in:
* **Pointer Arithmetic:** Navigating memory offsets safely and accurately.
* **File I/O Operations:** Reading raw binary data directly from disk.
* **Low-Level Reverse Engineering:** Understanding how Windows loads and executes binaries.

Currently, the tool is strictly focused on identifying and mapping the **Import Address Table (IAT)** to reveal dependencies and imported functions for both 32-bit and 64-bit executables.

## 🚀 Usage

To use this tool, compile the C code and pass the target executable as an argument:

```bash
# Example
./readpe.exe target_program.exe

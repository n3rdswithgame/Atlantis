# Atlantis

This is a emulator for the GameBoy Advance.

-----

[![Build Status](https://travis-ci.org/n3rdswithgame/Atlantis.svg?branch=develop)](https://travis-ci.org/n3rdswithgame/Atlantis)[![Build status](https://ci.appveyor.com/api/projects/status/dbm877lh1ywhudhc/branch/develop?svg=true)](https://ci.appveyor.com/project/n3rdswithgame/atlantis/branch/develop)

-----

## About

### Why call it Atlantis
There is a rumor going around online that the codename for the GBA was Atlantis, and I am a fan of the Stargate franchise, so the name kinda seemed like a good idea.

### How do I use it
This project is still very early in its development and is very much a WIP. It is still fairly far from being able to emulate the GameBoy Advance, with quite a bit of work in multiple areas in the emulator.

If you for whatever reason want to try and use Atlantis in its current state, build it, then `./atlantis -r [path to rom] -b [path to bios]` (or without the `./` for windows). As of the current commit, this just opens the rom file and bios and them immediatly exits.

A technical TODO of what still needs to be doen before it can boot any application

* Finish the decoding of arm instructions
* Start the decoding of thumb instructions
* Start an executor to apply the decoded instructions to the cpu

### Why make another GBA emulator?
There are a lot of other GBA emulators out there (mgba, the variosu vba forks, virtual console, ...), some even increadibly accurate. This is not intended to be a competitor to those other emulators. Having spent quite a bit of time reverse engineering ARM executables, I wanted to gain a better understanding of the architecture by coming at it from the other end. Additionally, this project is a good opertunity to learn the new c++17 features and best practices.

## Design
The end design of this emulator I think is novel enough to talk a little abou it. One of the main goals is to prioritize accuracy over speed, and the design tries to reflect that. Certain core parts try to be as generic as possible (mainly using CRTP), to allow potential expansions into other emulated systems. As this project is still in progress, this section might get updated until an alpha release. As these get implemented I will probalby write a DESIGN.md that will explain a bit more of the technicals of the design. 

In its faithful setting, the guest system will speculatively execute instructions (specifically a "microcoded" action from each instruction), and after sufficient time to ensure the speculation is correct (ie no interupts or no writes by other chips to a relevant address), the speculative execution will be committed. The idea being that in a faithful setting any interupts can happen on an instruction boundary. This is definetly not the most efficient way of emulating, but faithful mode is meant for accuracy instead of efficientcy, atleast currently.

There are plans for other emulation modes that will provide less accuracy for more useability and efficiency.

* In an interpreter mode there will be no epeculative execution. Additionally for hot code paths there will be an optimzier to try and optimzie the microcode for each basic block. In this mode, any interupt will happen on a group of instruction bondary.

* In a planned JITed mode, there will a JIT backend (most likely going to be llvm but potentially another) that will JIT each basic block to try and execute as quickly as possible with potential loss of accuracy. 

## Note on Piracy
This project by no means encourages or even condone the use of piracy. You are encouraged to write your own homebrew applications, or if you want to try games then please dump them yourselves (pleanty of methods online on how to do that). Currently there is no high level emulation of the bios, so that is also required and again please [dump it yourself](https://gist.github.com/MerryMage/797c523724e2dc02ada86a1cfadea3ee).

Please do not just go into google and search for roms or the GBA bios.

## License
This project is currently licensed under the MIT license. There is a potential I will add 2nd more restrictive license so it will be dual MIT and ___. If for whatever reason you might want to use this under a different license, email me (not gonna post it here because of webcrawlers, but its in the git log).
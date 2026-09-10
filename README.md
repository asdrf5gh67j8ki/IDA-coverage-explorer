# coverage explorer
A small IDA plugin for seeing what code executed when the target application ran.

Import a coverage log (`.log` file) and it will highlight the code in your disassembly. The highlights mean the code was observed executing in the imported recording.

It doesn't record execution itself. You need a log from something like DynamoRIO drcov, recorded from the same binary you're looking at in IDA.

You can compare runs as well. B - A shows code seen in B but not A. Useful for finding what gets reached when you do something different in a program.

On Windows, run `install.ps1`, restart IDA, then press `Ctrl+Alt+C` to import your log. Double-click a function to jump to it.
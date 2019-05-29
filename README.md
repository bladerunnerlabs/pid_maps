# pid_maps
kernel module to show vma maps of a process

## Building
`make`

All build products are stored in `build` directory. To clean:

`make clean`

## Loading
`insmod build/pid_maps.ko`

## Listing a process vma map list
To create a pid entry:

`echo ${pid} > /sys/kernel/debug/pid_maps/pid`

To print the maps:

`cat /sys/kernel/debug/pid_maps/${pid}`

If `${pid}` does not exist, the output will be: `Invalid argument`

Anyway `dmesg` should print relevant info and error messages.

## Unloading
`rmmod pid_maps`


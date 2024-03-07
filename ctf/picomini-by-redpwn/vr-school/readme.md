# vuln

uaf when deleting a student

## arbitrary function pointer exec, read


1. allocate student 0
2. allocate student 1
3. free student 0
4. allocate name for student 1 of size 0x18 (student struct size)
5. construct a fake student object as name (c++ vtable, the function pointer gets dereferenced and then jumped to)
6. exec function pointer or print name

## leaking program base

1. allocate student 0 with name of size 0x18
2. fill 0x20 tcache to size 6
3. free student 0 -- this frees the name first and then the student struct. tcache max size is 7, so the name chunk goes into tcache and the student struct alloc goes elsewhere
4. allocate student 1 -- this reuses the name struct of student 0
5. allocate name for student 1
6. print student 0 name to extract student 1 data
7. cout for char* is null terminated; gets you a program address, letting you leak program base


## so how do we exploit this?

at function pointer call rsi is 0 (aka O_RDONLY) and rdi is the student struct
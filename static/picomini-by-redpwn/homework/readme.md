### system

stack of size 100
"board" of 32 rows, 16 columns
can preload the first 4 rows with instructions

starting state is pcx = 0, pcy = 0, dirx = 1, diry = 0, cols = 16, rows = 32

every step it loads board[pcy \* 0x16 + pcx], executes the instruction, and then performs

pcx = (pcx + dirx + cols) % cols
pcy = (pcy + diry + rows) % rows

memory layout is

dirx -> sn -> stack -> board -> rows -> cols -> diry -> pcx -> pcy -> some garbage memory -> flag

### opcodes

#### 0x21 - !

requires sn >= 1
```text
stack[sn-1] = stack[sn-1] == 0
```
#### default (0)

requires sn < 100
```text
stack[sn] = 0
sn += 1
```

#### 0x24 - $

requires sn >= 1
```text
sn--
```
#### 0x25 - %

requires sn >= 2

```text
stack[sn-2] = stack[sn-2] % stack[sn-1]
sn--
```
#### 0x2a - *

requires sn >= 2

```text
stack[sn-2] = stack[sn-2] \* stack[sn-1]
sn--
```
#### 0x2b - +

requires sn >= 2

```text
stack[sn-2] = stack[sn-2] + stack[sn-1]
sn--
```
#### 0x2c - ,

requires sn >= 1

```text
sn--
putchar(stack[sn])
```
#### 0x2d - -

requires sn >= 2

```text
stack[sn-2] = stack[sn-2] - stack[sn-1]
sn--
```
#### 0x2e - .

requires sn >= 1

```text
sn--
printf("%d", stack[sn])
```
#### 0x2f - -

requires sn >= 2

```text
stack[sn-2] = stack[sn-2] / stack[sn-1]
sn--
```

#### 0x3a - :

requires sn >= 1

```text
stack[sn] = stack[sn-1]
sn++
```
overflows stack, instruction memory is directly after stack though

#### 0x3c - <

```text
dirx = -1
diry = 0
```
#### 0x3e - >

```text
dirx = 1
diry = 0
```

#### 0x40 - @

terminate execution

#### 0x5c - \

requires sn >= 2

swaps stack[sn-1] and stack[sn-2]

#### 0x5e - ^

```text
dirx = 0
diry = -1
```
#### 0x5f - _

requires sn >= 1

```text
sn--
if stack[sn] == 0 {
	dirx = 1
	diry = 0
} else {
	dirx = -1
	diry = 0
}
```

#### 0x60 - \`

requires sn >= 2

```text
stack[sn-2] = stack[sn-1] < stack[sn-2]
```

#### 0x67 - g

requires sn >= 2, stack[sn-2] >= 0, stack[sn-1] >= 0, stack[sn-1] <= rows, stack[sn-2] <= cols

```text
stack[sn-2] = board[stack[sn-1] * 0x16 + stack[sn-2]]
sn--
```

#### 0x70 - p

requires sn >= 3, stack[sn-2] >= 0, stack[sn-1] >= 0, stack[sn-1] <= rows, stack[sn-2] <= cols

```text
board[stack[sn-1] * 0x16 + stack[sn-2]] = stack[sn-3]
sn -= 3
```
#### 0x76 - v

```text
dirx = 0
diry = 1
```

#### 0x7c

requires sn >= 1

```text
sn--
if(stack[sn] == 0) {
	dirx = 0;
	diry = 1;
} else {
	dirx = 0;
	diry = -1;
}
```
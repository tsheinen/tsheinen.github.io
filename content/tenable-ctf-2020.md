+++
title = "Tenable CTF 2020"
date = 2021-02-20

[taxonomies]
tags = ["ctf-writeups"]
+++

Tenable (the company who makes Nessus) ran a capture the flag over the weekend of February 19th.  I played for a few hours saturday night and pretty much cleared out the code category.  I've been a little starved for programming recently so I went straight for it haha.  Overall I'd say it was a pretty solid CTF -- I didn't devote the time needed to scope out every challenge but I had a fun time while I was playing.
<!-- more -->

## code

### short and sweet

```python
def AreNumbersEven(numbers):
  return [x % 2 == 0 for x in numbers]

# Read space delimited integers from stdin and 
# pass a list of them to AreNumbersEven()
numbers = raw_input()
integer_list = [int(i) for i in numbers.split(' ')]
even_odd_boolean_list = AreNumbersEven(integer_list)
print even_odd_boolean_list 
```

### hello ${name}

```c
#include <stdio.h>
int main()
{
	char buf[32];
	fgets(buf,32,stdin);
	printf("Hello %s", buf);
    return 0;
}
```

### print N lowest numbers

```c++
#include <iostream>
#include <algorithm>
#include <vector>
void PrintNLowestNumbers(int arr[], unsigned int length, unsigned short nLowest)
{
	std::vector<int> vec(arr, arr + length);

	std::sort(vec.begin(),vec.end());
	int i = 0;
	for(; i < nLowest - 1; i++) {
		std::cout << vec[i] << " ";
	}
	std::cout << vec[i];
}

int main()
{
	char input[0x100];
	int integerList[0x100];
	unsigned int length;
	unsigned short nLowest;
	std::cin >> nLowest;
	std::cin >> length;
	for (int i=0;i<length;i++)
		 std::cin >> integerList[i];
	PrintNLowestNumbers(integerList, length, nLowest);
}
```

### parsey mcparser

```python
import re

'''
:param blob: blob of data to parse through (string)
:param group_name: A single Group name ("Green", "Red", or "Yellow",etc...)

:return: A list of all user names that are part of a given Group
'''
def ParseNamesByGroup(blob, group_name):
    # print(group_name)
    matches = re.findall("\[(.*?)\]", blob)
    return [x['user_name'] for x in [eval("{{{}}}".format(i)) for i in matches] if x['Group'] == group_name]
    
data = raw_input()
group_name = data.split('|')[0]
blob = data.split('|')[1]
result_names_list = ParseNamesByGroup(blob, group_name)
print(result_names_list)
```

### random encryption

lmao it was in the provided source code hate to see it

flag: flag{n0t_that_r4ndom}

### random encryption fixed

```python
import random
# flag = "flag{not_the_flag}"
res = [184, 161, 235, 97, 140, 111, 84, 182, 162, 135, 76, 10, 69, 246, 195, 152, 133, 88, 229, 104, 111, 22, 39]
seeds = [9925, 8861, 5738, 1649, 2696, 6926, 1839, 7825, 6434, 9699, 227, 7379, 9024, 817, 4022, 7129, 1096, 4149, 6147, 2966, 1027, 4350, 4272]

for i in range(0, len(res)):
    random.seed(seeds[i])
    rands = []
    for j in range(0,4):
        rands.append(random.randint(0,255))
    print(chr(rands[i%4] ^ res[i]),end="")
```

### find largest triangle

```python
#determinant of matrix a
def det(a):
    return a[0][0]*a[1][1]*a[2][2] + a[0][1]*a[1][2]*a[2][0] + a[0][2]*a[1][0]*a[2][1] - a[0][2]*a[1][1]*a[2][0] - a[0][1]*a[1][0]*a[2][2] - a[0][0]*a[1][2]*a[2][1]

#unit normal vector of plane defined by points a, b, and c
def unit_normal(a, b, c):
    x = det([[1,a[1],a[2]],
             [1,b[1],b[2]],
             [1,c[1],c[2]]])
    y = det([[a[0],1,a[2]],
             [b[0],1,b[2]],
             [c[0],1,c[2]]])
    z = det([[a[0],a[1],1],
             [b[0],b[1],1],
             [c[0],c[1],1]])
    magnitude = (x**2 + y**2 + z**2)**.5
    return (x/magnitude, y/magnitude, z/magnitude)

#dot product of vectors a and b
def dot(a, b):
    return a[0]*b[0] + a[1]*b[1] + a[2]*b[2]

#cross product of vectors a and b
def cross(a, b):
    x = a[1] * b[2] - a[2] * b[1]
    y = a[2] * b[0] - a[0] * b[2]
    z = a[0] * b[1] - a[1] * b[0]
    return (x, y, z)


#area of polygon poly
def area(poly):
    if len(poly) < 3: # not a plane - no area
        return 0

    total = [0, 0, 0]
    for i in range(len(poly)):
        vi1 = poly[i]
        if i is len(poly)-1:
            vi2 = poly[0]
        else:
            vi2 = poly[i+1]
        prod = cross(vi1, vi2)
        total[0] += prod[0]
        total[1] += prod[1]
        total[2] += prod[2]
    result = dot(total, unit_normal(poly[0], poly[1], poly[2]))
    return abs(result/2)
from itertools import combinations

# points is a list of 3D points
# ie: [[2, 9, -15], [0, 33, -20], ...]
def FindLargestTriangleArea(points):
  # return largest area
  return max([area(x) for x in combinations(points,3)])

# Reading space delimited points from stdin
# and building list of 3D points
# points_data = "-21,59,-93 -4,91,-2 1,61,2, 0,44,1"
points_data = raw_input()
points = []
for point in points_data.split(' '):
  point_xyz = point.split(',')
  points.append([int(point_xyz[0]), int(point_xyz[1]), int(point_xyz[2])])

# Compute Largest Triangle and Print Area rounded to nearest whole number
area = FindLargestTriangleArea(points)
print(int(round(area)))
```


### we need an emulator

```rust
/*
[package]
name = "tenable-emu"
version = "0.1.0"
authors = ["Teddy Heinen <teddy@heinen.dev>"]
edition = "2018"

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

[dependencies]
nom = "6.1.2"
*/

use nom::branch::alt;
use nom::bytes::complete::{tag, take_until};
use nom::combinator::opt;
use nom::multi::many1;
use nom::{Finish, IResult};
use std::collections::HashMap;

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
enum Register {
    Trx,
    Drx,
}

#[derive(Debug, Clone)]
enum Instruction {
    Xor(Register, Register),
    MovL(Register, String),
    Mov(Register, Register),
    Reverse(Register),
}

fn instruction(input: &str) -> IResult<&str, Instruction> {
    fn register(input: &str) -> IResult<&str, Register> {
        fn trx(input: &str) -> IResult<&str, Register> {
            let (input, _) = tag("TRX")(input)?;
            Ok((input, Register::Trx))
        }

        fn drx(input: &str) -> IResult<&str, Register> {
            let (input, _) = tag("DRX")(input)?;
            Ok((input, Register::Drx))
        }
        alt((trx, drx))(input)
    }

    fn xor(input: &str) -> IResult<&str, Instruction> {
        let (input, _) = tag("XOR ")(input)?;
        let (input, lhs) = register(input)?;
        let (input, _) = tag(" ")(input)?;
        let (input, rhs) = register(input)?;
        let (input, _) = opt(tag("\r\n"))(input)?;
        Ok((input, Instruction::Xor(lhs, rhs)))
    }

    fn movl(input: &str) -> IResult<&str, Instruction> {
        let (input, _) = tag("MOV ")(input)?;
        let (input, lhs) = register(input)?;
        let (input, _) = tag(" \"")(input)?;
        let (input, rhs) = take_until("\"")(input)?;
        let (input, _) = tag("\"")(input)?;
        let (input, _) = opt(tag("\r\n"))(input)?;
        Ok((input, Instruction::MovL(lhs, rhs.to_string())))
    }

    fn mov(input: &str) -> IResult<&str, Instruction> {
        let (input, _) = tag("MOV ")(input)?;
        let (input, lhs) = register(input)?;
        let (input, _) = tag(" ")(input)?;
        let (input, rhs) = register(input)?;
        let (input, _) = opt(tag("\r\n"))(input)?;
        Ok((input, Instruction::Mov(lhs, rhs)))
    }
    fn reverse(input: &str) -> IResult<&str, Instruction> {
        let (input, _) = tag("REVERSE ")(input)?;
        let (input, lhs) = register(input)?;
        let (input, _) = opt(tag("\r\n"))(input)?;
        Ok((input, Instruction::Reverse(lhs)))
    }

    alt((xor, movl, mov, reverse))(input)
}

#[derive(Debug, Default, Clone)]
struct State {
    registers: HashMap<Register, Vec<u8>>,
}

impl State {
    fn apply(&mut self, instr: Instruction) -> &mut Self {
        match instr {
            Instruction::Xor(lhs, rhs) => {
                let lhs_reg = self.registers.get(&lhs).unwrap().clone();
                let rhs_reg = self.registers.get(&rhs).unwrap().clone();

                let new_val = lhs_reg
                    .into_iter()
                    .enumerate()
                    .map(|(index, x)| x ^ rhs_reg.get(index).unwrap_or(&0u8))
                    .collect::<Vec<_>>();

                self.registers.insert(lhs, new_val);
            }
            Instruction::MovL(lhs, rhs) => {
                self.registers.insert(lhs, rhs.bytes().collect());
            }
            Instruction::Mov(lhs, rhs) => {
                let rhs_reg = self.registers.get(&rhs).unwrap().clone();
                self.registers.insert(lhs, rhs_reg);
            }
            Instruction::Reverse(lhs) => {
                let lhs_reg = self.registers.get(&lhs).unwrap().clone();
                self.registers
                    .insert(lhs, lhs_reg.iter().cloned().rev().collect::<Vec<_>>());
            }
        };
        self
    }
}

fn main() {
    let crypto = include_str!("../../Crypto.asm");

    let (_, instructions) = many1(instruction)(crypto).finish().unwrap();

    let mut state = State::default();
    state
        .registers
        .insert(Register::Trx, b"GED\x03hG\x15&Ka =;\x0c\x1a31o*5M".to_vec());
    state.registers.insert(Register::Drx, b"".to_vec());
    println!(
        "{:?}",
        String::from_utf8_lossy(
            &instructions
                .into_iter()
                .fold(&mut state, |st, instr| st.apply(instr))
                .registers
                .get(&Register::Trx)
                .unwrap()
                .clone()
        )
    );
}
```

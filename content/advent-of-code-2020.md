+++
title = "Advent of Code 2020"
date = 2020-12-01

[taxonomies]
tags = []
+++

Advent of Code is a yearly coding event which takes place in December.  Every day we get a new short programming exercise with a cute christmas themed story.  Historically I've had a lot of fun solving them but the difficulty increases with every day and i've never finished.  I'm pretty invested in finishing this year so we'll see how far I get!  I'll update this every few days or so once i'm satisfied with my solution but if you'd like to see up-to-date information all of my solutions are on [GitHub](https://github.com/tcheinen/advent-of-code-2020)

<!-- more -->

# Day 1: Report Repair


> After saving Christmas five years in a row, you've decided to take a vacation at a nice resort on a tropical island. Surely, Christmas will go on without you.
>
> The tropical island has its own currency and is entirely cash-only. The gold coins used there have a little picture of a starfish; the locals just call them stars. None of the currency exchanges seem to have heard of them, but somehow, you'll need to find fifty of these coins by the time you arrive so you can pay the deposit on your room.
>
>To save your vacation, you need to get all fifty stars by December 25th.
>
>Collect stars by solving puzzles. Two puzzles will be made available on each day in the Advent calendar; the second puzzle is unlocked when you complete the first. Each puzzle grants one star. Good luck!


## Part One

>Before you leave, the Elves in accounting just need you to fix your expense report (your puzzle input); apparently, something isn't quite adding up.
>
>Specifically, they need you to find the two entries that sum to 2020 and then multiply those two numbers together.
>
>For example, suppose your expense report contained the following:

```text
1721
979
366
299
675
1456
```

>In this list, the two entries that sum to 2020 are 1721 and 299. Multiplying them together produces 1721 * 299 = 514579, so the correct answer is 514579.
>
>Of course, your expense report is much larger. Find the two entries that sum to 2020; what do you get if you multiply them together?

### Solution

```rust
#[aoc_generator(day1)]
pub fn generator(input: &str) -> Vec<u32> {
    input.split("\n").flat_map(|x| x.parse()).collect()
}

#[aoc(day1, part1)]
pub fn solve_part1(input: &[u32]) -> u32 {
    input
        .iter()
        .zip(std::iter::repeat(
            &input.iter().cloned().collect::<HashSet<u32>>(),
        ))
        .find(|(x, nums)| nums.contains(&(2020 - **x)))
        .map(|(x, _)| x * (2020 - *x))
        .unwrap()
}
```

The dataset we're running this on is small enough that we could honestly just do the obvious n^2 algorithm (checking every pair a,b) but that's no fun and I want to optimize.  The key here is that `a + b = c` is the same as `c - a = b`.  If we know c and a then we can solve for b.  Now, we still need to check if b is inside the data but we can do that with the humble hash set.  Hash sets allow for checking membership in constant time which means our final algorithm is only linear.  

## Part Two

>The Elves in accounting are thankful for your help; one of them even offers you a starfish coin they had left over from a past vacation. They offer you a second one if you can find three numbers in your expense report that meet the same criteria.
>
>Using the above example again, the three entries that sum to 2020 are 979, 366, and 675. Multiplying them together produces the answer, 241861950.
>
>In your expense report, what is the product of the three entries that sum to 2020?

### Solution

```rust
#[aoc(day1, part2)]
pub fn solve_part2(input: &[u32]) -> u32 {
    input
        .iter()
        .sorted()
        .flat_map(|a| {
            input
                .iter()
                .filter(|x| **x < (2020 - *a))
                .map(|x| (a, x))
                .collect::<Vec<_>>()
                .into_iter()
        })
        .zip(std::iter::repeat(
            &input.iter().cloned().collect::<HashSet<u32>>(),
        ))
        .find(|((a, b), nums)| nums.contains(&(2020 - **a - **b)))
        .map(|((a, b), _)| *a * *b * (2020 - *a - *b))
        .unwrap()
}
```

Part Two is very similar to part one except we're searching for a pair a,b,c instead.  Again, the naive solution works fine on the input but it's honestly a little boring.  Similarly to part 1 the idea behind this is that for `a + b + c = d` we can solve for any of the four variables if we know the other three.  We can then check for set membership in constant time with a hashset.  I did a couple minor optimizations which worked because of the input distribution: Sorting the input first and then filtering my pair to only include elements which sum up to less than 2020.  The bulk of the input are larger numbers so we know that it is very likely that two of the chosen numbers will be smaller.  Sorting it first means that with very high probability the answer will be found near the beginning of the loop instead of somewhere in the middle.  

# Day 2: Password Philosophy

>Your flight departs in a few days from the coastal airport; the easiest way down to the coast from here is via toboggan.
>
>The shopkeeper at the North Pole Toboggan Rental Shop is having a bad day. "Something's wrong with our computers; we can't log in!" You ask if you can take a look.
>
>Their password database seems to be a little corrupted: some of the passwords wouldn't have been allowed by the Official Toboggan Corporate Policy that was in effect when they were chosen.

## Part One

>To try to debug the problem, they have created a list (your puzzle input) of passwords (according to the corrupted database) and the corporate policy when that password was set.
>
>For example, suppose you have the following list:

```text
1-3 a: abcde
1-3 b: cdefg
2-9 c: ccccccccc
```

>Each line gives the password policy and then the password. The password policy indicates the lowest and highest number of times a given letter must appear for the password to be valid. For example, 1-3 a means that the password must contain a at least 1 time and at most 3 times.
>
>In the above example, 2 passwords are valid. The middle password, cdefg, is not; it contains no instances of b, but needs at least 1. The first and third passwords are valid: they contain one a or nine c, both within the limits of their respective policies.
>
>How many passwords are valid according to their policies?

### Solution

```rust
#[derive(Clone)]
pub struct Policy {
    min: usize,
    max: usize,
    letter: char,
}

#[aoc_generator(day2)]
pub fn generator(input: &str) -> Vec<(Policy, String)> {
    input
        .split("\n")
        .filter_map(|x| x.split(": ").collect_tuple::<(&str, &str)>())
        .filter_map(|(a, b)| Some((a.split(" ").collect_tuple::<(&str, &str)>()?, b)))
        .filter_map(|((range, letter), password)| {
            Some((
                range.split("-").collect_tuple::<(&str, &str)>()?,
                letter,
                password,
            ))
        })
        .filter_map(|((min, max), letter, password)| {
            Some((
                Policy {
                    min: min.parse().ok()?,
                    max: max.parse().ok()?,
                    letter: letter.chars().next()?,
                },
                password.to_string(),
            ))
        })
        .collect()
}

#[aoc(day2, part1)]
pub fn solve_part1(input: &[(Policy, String)]) -> usize {
    input
        .iter()
        .filter(|(policy, password)| {
            (policy.min..=policy.max)
                .contains(&password.chars().filter(|x| *x == policy.letter).count())
        })
        .count()
}
```

The bulk of the effort here is in the input parsing.  Fortunately, the input is simple enough that I can afford to be lazy and just split the string repeatedly.  

Once the input has been parsed the actual solution is trivial -- just count how many times a password has a given character and then count the number of passwords for which that number is within the provided range. 

## Part Two

>While it appears you validated the passwords correctly, they don't seem to be what the Official Toboggan Corporate Authentication System is expecting.
>
>The shopkeeper suddenly realizes that he just accidentally explained the password policy rules from his old job at the sled rental place down the street! The Official Toboggan Corporate Policy actually works a little differently.
>
>Each policy actually describes two positions in the password, where 1 means the first character, 2 means the second character, and so on. (Be careful; Toboggan Corporate Policies have no concept of "index zero"!) Exactly one of these positions must contain the given letter. Other occurrences of the letter are irrelevant for the purposes of policy enforcement.
>
>Given the same example list from above:
>
>    1-3 a: abcde is valid: position 1 contains a and position 3 does not.
>    1-3 b: cdefg is invalid: neither position 1 nor position 3 contains b.
>    2-9 c: ccccccccc is invalid: both position 2 and position 9 contain c.
>
>How many passwords are valid according to the new interpretation of the policies?

```rust
#[aoc(day2, part2)]
pub fn solve_part2(input: &[(Policy, String)]) -> usize {
    input
        .iter()
        .filter(|(policy, password)| {
            (password.chars().nth(policy.min - 1).unwrap_or('\x00') == policy.letter)
                != (password.chars().nth(policy.max - 1).unwrap_or('\x00') == policy.letter)
        })
        .count()
}
```

For part two instead of counting the occurrences of the letter we are instead checking only two positions (min and max from the previous problem, indexed starting at 1).  A password is valid if it contains that letter only in one of those positions.  To solve this problem we just need to count the number of passwords for which that property is true.  
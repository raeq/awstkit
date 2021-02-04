# Amazon Web Services Toolkit

## Tools in the toolkit:

```
Usage: awstkit.py [OPTIONS] COMMAND [ARGS]...

  cli.

Options:
  -V      Show the version and exit.
  --help  Show this message and exit.

Commands:
  checkcerts    Checks all ACM Certificates in a region or globally.
  findami       Finds information about AMIs, given a list of ids.
  listaccounts  Lists all accounts in an Organization.

```

## findami

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

```
Usage: awstkit.py listaccounts [OPTIONS]

  Lists all accounts in an Organization.

Options:
  -p, --profile TEXT  The awscli configuration profile for the master account.
  --help              Show this message and exit.


```



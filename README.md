# Amazon Web Services Toolkit

## Tools in the toolkit:

## findami

Helpful if you know the Id of an AMI, but don't know which region it is in.

```
Usage: awstkit.py findami [OPTIONS] AMI_ID...

  Finds information about AMIs, given a list of ids.

  Arguments:     ami_id {[string]} -- A list of ami IDs.     region {String}
  -- The single region to search.     allregions {Flag} -- Set this flag if
  all regions are to be searched.

Options:
  -r, --region TEXT   Restrict search to this single region
  -p, --profile TEXT  The awscli configuration profile for the master account.
  --help              Show this message and exit.

```

## checkcerts

Helps you to understand your certificates. Iterates through every region and throws an error about invalid client
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

Lists all the OUs and their accounts in your AWS Organization. Throws an error if your profile is not the
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

## reachability

Perform a reachability test to see if an eni has routing from a source ip address.

Can take a very long time in a large account with many VPCs and enis or instances. Use the ```--region```
and ```--vpc_destination``` flags to be more specific.

Example:

```
awstkit.py reachability -s 8.8.8.8 -d 10.0.113.30 -r us-east-1 -vd vpc-XXXXXXXXXX
```

Example results:

```
(['The searched for IP address 10.0.113.30 was found but is not in use.',
  'No security group ingress rule found from source 8.8.8.8.'],
 ['The searched for IP address 10.0.113.30 exists in the given VPC vpc-0ee3f414da7392532',
  'There is an attached and available IGW igw-0abca0b589549b2cc for vpc vpc-0ee3f414da7392532',
  'The subnet used by the ip 10.0.113.30 has the range 10.0.0.0/17 and has the state available ',
  'The main route table has a route to the IGW igw-0abca0b589549b2cc ',
  'Egress rule #100 allows egress to 0.0.0.0/0 using protocol -1  in acl-066fd04990e07e939',
  'Ingress rule #100 allows ingress from 0.0.0.0/0 using protocol -1 in acl-066fd04990e07e939',
  'Security group sg-0c539e6d394ec7dd8 "default" allows egress to 0.0.0.0/0 on protocol -1 from 10.0.113.30'])

```

```
Usage: awstkit.py reachability [OPTIONS]

  Tests the reachability of IP addresses.

Options:
  -r, --region TEXT            Restrict search to this single region
  -p, --profile TEXT           The awscli configuration profile for the master
                               account.

  -vd, --vpc_destination TEXT  Restrict search to this specific destination
                               vpc

  -s, --source TEXT            The source IP address
  -d, --destination TEXT       The destination IP address
  --help                       Show this message and exit.
```

## aggregate-resources

Will use an AWS Config Aggregator to list resources of the specified type. The default type is "AWS::EC2::Instance". If
you don't have an aggregator configured within the scope of the profile you're using, this won't work.

If you can't remember the name of the aggregator you'd like to use, or if you forget to specify it, the script will
attempt to use the first aggregator it finds.

```
Usage: awstkit.py aggregate-resources [OPTIONS]

  Returns the resources in the chosen config resource aggregator.

Options:
  -p, --profile TEXT         The awscli configuration profile for the master
                             account.

  -rt, --resource_type TEXT  Restrict search to this specific resource type.
  -ag, --aggregator TEXT     Use this AWS Config Aggregator name.
  --help                     Show this message and exit.

```


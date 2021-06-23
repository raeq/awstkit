import logging

import backoff
import boto3


@backoff.on_exception(backoff.expo, Exception)
def get_resources(resource_type: str = "AWS::EC2::Instance", profile: str = "default",
                  aggregator: str = "") -> dict:
    """
    Get the resources of a specified type from the specified config aggregator.
    Uses the first available aggregator if no aggregator is specified. Or it dies with an error.
    This is a generator, yielding individual resources. Loop over it to a acuomatically call __next__()

    :param resource_type:
    :type resource_type:
    :param profile:
    :type profile:
    :param aggregator:
    :type aggregator:
    :return:
    :rtype: A dict describing a resource
    """
    logger = logging.getLogger(__name__)

    session = boto3.session.Session(profile_name = profile)
    config = session.client("config")

    if not aggregator:
        # no aggregator name given
        # let's try to get the first one available
        try:
            aggregator = config.describe_configuration_aggregators().get("ConfigurationAggregators")[0].get(
                    "ConfigurationAggregatorName")
        except IndexError as e:
            logger.exception(e)
            print("You do not have any resource aggregations in AWS Config.")
            return

    results: list = []
    logger.debug(f'Accessing config aggregator for resource type: {resource_type} '
                 f'using aggregator: {aggregator} '
                 f'using profile: {profile}')

    paginator = config.get_paginator("list_aggregate_discovered_resources")
    iterator = paginator.paginate(ConfigurationAggregatorName = aggregator,
                                  ResourceType = resource_type)
    for page in iterator:
        for item in page.get("ResourceIdentifiers"):
            yield item


if __name__ == '__main__':
    for k, v in enumerate(get_resources()):
        d: list = list(dict(v).values())
        print(k, " ".join(d))

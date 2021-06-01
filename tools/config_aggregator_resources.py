import logging

import backoff
import boto3


@backoff.on_exception(backoff.expo, Exception)
def get_resources(resource_type: str = "AWS::EC2::Instance", profile: str = "",
                  aggregator: str = "") -> dict:
    logger = logging.getLogger(__name__)

    session = boto3.session.Session(profile_name = profile)
    config = session.client("config")

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

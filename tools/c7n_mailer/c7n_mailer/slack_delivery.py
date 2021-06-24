# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import time

import requests
from c7n_mailer.ldap_lookup import Redis
from c7n_mailer.utils import get_rendered_jinja
from c7n_mailer.utils_email import is_email


class SlackDelivery:

    def __init__(self, config, logger, email_handler):
        self.caching = self.cache_factory(config, config.get('cache_engine', None))
        self.config = config
        self.logger = logger
        self.email_handler = email_handler

    def cache_factory(self, config, type):
        if type == 'redis':
            return Redis(redis_host=config.get('redis_host'),
                         redis_port=int(config.get('redis_port', 6379)), db=0)
        else:
            return None

    def get_to_addrs_slack_messages_map(self, sqs_message):
        resource_list = []
        for resource in sqs_message['resources']:
            resource_list.append(resource)

        slack_messages = {}

        # Check for Slack targets in 'to' action and render appropriate template.
        for target in sqs_message.get('action', ()).get('to'):
            if target == 'slack://owners':
                #target_tags = sqs_message.get('action', ()).get('owner_tag')
                target_tags = self.config.get('contact_tags', [])
                resource_groups = {}
                for resource_item in resource_list:
                    owner_tag_found = False
                    #Look through the tags that exist in the config file for owners
                    for target_tag in target_tags:
                        new_owner = ''
                        for t in resource_item.get('Tags'):
                            if t.get('Key') == target_tag:
                                new_owner = t.get('Value')
                        if not new_owner == '':
                            owner_tag_found = True
                            #check that there is a valid email for the user if not add it to the default email
                            if not "@" in new_owner:
                                new_owner = new_owner +  sqs_message.get('action', ()).get('default_email')
                            if not new_owner in resource_groups.keys():
                                resource_groups[new_owner] = [resource_item]
                            else:
                                #This prevents double messages to the same person
                                if not resource_item in resource_groups.get(new_owner):
                                    resource_groups.get(new_owner).append(resource_item)
                    #if no owner tag is present use the default messaging that was set. 
                    if not owner_tag_found:
                        for owner_absent_contact in sqs_message.get('action', ()).get('owner_absent_contact'):
                            if not owner_absent_contact in resource_groups.keys():
                                    resource_groups[owner_absent_contact] = [resource_item]
                            else:
                                if not resource_item in resource_groups.get(owner_absent_contact):
                                    resource_groups.get(owner_absent_contact).append(resource_item)
                #loop through all the values and send them off to the owners
                for list_owner, value in resource_groups.items():
                    resolved_addrs = self.retrieve_user_im([list_owner])
                    for address, slack_target in resolved_addrs.items():
                        slack_messages[address] = get_rendered_jinja(
                            slack_target, sqs_message, value,
                            self.logger, 'slack_template', 'slack_default',
                            self.config['templates_folders'])
            elif target.startswith('https://hooks.slack.com/'):
                slack_messages[target] = get_rendered_jinja(
                    target, sqs_message,
                    resource_list,
                    self.logger, 'slack_template', 'slack_default',
                    self.config['templates_folders'])
            elif target.startswith('slack://webhook/#') and self.config.get('slack_webhook'):
                webhook_target = self.config.get('slack_webhook')
                slack_messages[webhook_target] = get_rendered_jinja(
                    target.split('slack://webhook/#', 1)[1], sqs_message,
                    resource_list,
                    self.logger, 'slack_template', 'slack_default',
                    self.config['templates_folders'])
                self.logger.debug(
                    "Generating message for webhook %s." % self.config.get('slack_webhook'))
            elif target.startswith('slack://') and is_email(target.split('slack://', 1)[1]):
                resolved_addrs = self.retrieve_user_im([target.split('slack://', 1)[1]])
                for address, slack_target in resolved_addrs.items():
                    slack_messages[address] = get_rendered_jinja(
                        slack_target, sqs_message, resource_list,
                        self.logger, 'slack_template', 'slack_default',
                        self.config['templates_folders'])
            elif target.startswith('slack://#'):
                resolved_addrs = target.split('slack://#', 1)[1]
                slack_messages[resolved_addrs] = get_rendered_jinja(
                    resolved_addrs, sqs_message,
                    resource_list,
                    self.logger, 'slack_template', 'slack_default',
                    self.config['templates_folders'])
            elif target.startswith('slack://tag/') and 'Tags' in resource:
                tag_name = target.split('tag/', 1)[1]
                result = next((item for item in resource.get('Tags', [])
                               if item["Key"] == tag_name), None)
                if not result:
                    self.logger.debug(
                        "No %s tag found in resource." % tag_name)
                    continue

                resolved_addrs = result['Value']

                if not resolved_addrs.startswith("#"):
                    resolved_addrs = "#" + resolved_addrs

                slack_messages[resolved_addrs] = get_rendered_jinja(
                    resolved_addrs, sqs_message,
                    resource_list,
                    self.logger, 'slack_template', 'slack_default',
                    self.config['templates_folders'])
                self.logger.debug("Generating message for specified Slack channel.")
        return slack_messages

    def slack_handler(self, sqs_message, slack_messages):
        for key, payload in slack_messages.items():
            self.logger.info("Sending account:%s policy:%s %s:%s slack:%s to %s" % (
                sqs_message.get('account', ''),
                sqs_message['policy']['name'],
                sqs_message['policy']['resource'],
                str(len(sqs_message['resources'])),
                sqs_message['action'].get('slack_template', 'slack_default'),
                key)
            )

            self.send_slack_msg(key, payload)

    def retrieve_user_im(self, email_addresses):
        list = {}

        if not self.config['slack_token']:
            self.logger.info("No Slack token found.")

        for address in email_addresses:
            if self.caching and self.caching.get(address):
                self.logger.debug('Got Slack metadata from cache for: %s' % address)
                list[address] = self.caching.get(address)
                continue

            response = requests.post(
                url='https://slack.com/api/users.lookupByEmail',
                data={'email': address},
                headers={'Content-Type': 'application/x-www-form-urlencoded',
                         'Authorization': 'Bearer %s' % self.config.get('slack_token')}).json()

            if not response["ok"]:
                if "headers" in response.keys() and "Retry-After" in response["headers"]:
                    self.logger.info(
                        "Slack API rate limiting. Waiting %d seconds",
                        int(response.headers['retry-after']))
                    time.sleep(int(response.headers['Retry-After']))
                    continue
                elif response["error"] == "invalid_auth":
                    raise Exception("Invalid Slack token.")
                elif response["error"] == "users_not_found":
                    self.logger.info("Slack user ID for email address %s not found.", address)
                    if self.caching:
                        self.caching.set(address, {})
                    continue
                else:
                    self.logger.warning("Slack Response: {}".format(response))
            else:
                slack_user_id = response['user']['id']
                if 'enterprise_user' in response['user'].keys():
                    slack_user_id = response['user']['enterprise_user']['id']
                self.logger.debug(
                    "Slack account %s found for user %s", slack_user_id, address)
                if self.caching:
                    self.logger.debug('Writing user: %s metadata to cache.', address)
                    self.caching.set(address, slack_user_id)

                list[address] = slack_user_id

        return list

    def send_slack_msg(self, key, message_payload):

        if key.startswith('https://hooks.slack.com/'):
            response = requests.post(
                url=key,
                data=message_payload,
                headers={'Content-Type': 'application/json'})
        else:
            response = requests.post(
                url='https://slack.com/api/chat.postMessage',
                data=message_payload,
                headers={'Content-Type': 'application/json;charset=utf-8',
                         'Authorization': 'Bearer %s' % self.config.get('slack_token')})

        if response.status_code == 429 and "Retry-After" in response.headers:
            self.logger.info(
                "Slack API rate limiting. Waiting %d seconds",
                int(response.headers['Retry-After']))
            time.sleep(int(response.headers['Retry-After']))
            return

        elif response.status_code != 200:
            self.logger.info(
                "Error in sending Slack message status:%s response: %s",
                response.status_code, response.text)
            return

        if 'text/html' in response.headers['content-type']:
            if response.text != 'ok':
                self.logger.info("Error in sending Slack message. Status:%s, response:%s",
                                response.status_code, response.text)
                return

        else:
            response_json = response.json()
            if not response_json['ok']:
                self.logger.info("Error in sending Slack message. Status:%s, response:%s",
                                response.status_code, response_json['error'])
                return

import urllib3
from typing import Dict, Any, Tuple, List, Union

from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url: str):
        header = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        super().__init__(base_url=base_url, headers=header)

    def http_request(self, suffix: str) -> Union[Dict[str, Any], List[Dict[str, Any]]]:

        """Connects to api and Returns response.
           Args:
               suffix :The API endpoint.
           Returns:
               response from the api.
           """
        return self._http_request(method="GET", url_suffix=suffix)


def cve_to_context(cve):
    return {
        "ID": cve.get("id", ""),
        "CVSS": cve.get("cvss", "0"),
        "Published": cve.get("Published", "").rstrip("Z"),
        "Modified": cve.get("Modified", "").rstrip("Z"),
        "Description": cve.get("summary", '')
    }


def test_module(client: Client, *_):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    res = client.http_request(suffix="/last")
    if res:
        return "ok", None, None
    raise Exception('Error occurred while trying to query the api.')


def cve_search(client: Client, args: dict) -> Tuple[Any, Dict[str, List[Any]], List[Union[Dict[str, Any], List[Dict[str, Any]]]]]:
    cve_ids = args.get("cve_id")
    if not cve_ids:
        raise KeyError("cve_id argument not given")
    cve_ids = argToList(cve_ids)
    raw_response = []
    ec = []
    human_readable = []
    cve_ids_with_no_response = []
    for cve_id in cve_ids:
        res = client.http_request("cve/" + cve_id)
        if not res:
            # If there is no data in CVE-Search for a given cve-id the response will return None,
            # in this case these ids are stored in order to let the client know that querying those ids gave no results.
            cve_ids_with_no_response.append({"ID": cve_id})
            continue
        data = cve_to_context(res)
        raw_response.append(res)
        ec.append(data)
        human_readable.append(data)
    human_readable = tableToMarkdown("CVE Search results", human_readable)
    if cve_ids_with_no_response:
        # If there was cve-ids for which no results returned
        human_readable += tableToMarkdown("Could not find cve results for the following ids", cve_ids_with_no_response)
    context = {'CVE(val.ID === obj.ID)': ec} if ec else {}
    return human_readable, context, raw_response


def cve_latest(client: Client, *_) -> Tuple[Any, Dict[str, List[Any]], Union[Dict[str, Any], List[Dict[str, Any]]]]:
    ec = []
    human_readable = []
    res = client.http_request(suffix="/last")
    for cve_details in res:
        data = cve_to_context(cve_details)
        ec.append(data)
        human_readable.append(data)
    ec = {'CVE(val.ID === obj.ID)': ec}
    human_readable = tableToMarkdown("cicle.lu Latest CVEs", human_readable)
    return human_readable, ec, res


def cve(client: Client, args: dict) -> Tuple[Any, Dict[str, List[Any]], List[Union[Dict[str, Any], List[Dict[str, Any]]]]]:
    human_readable, ec, raw_response = cve_search(client, args)
    return human_readable, ec, raw_response


def main():
    params = demisto.params()
    # Service base URL
    base_url = params.get('url')
    client = Client(base_url=base_url)
    command = demisto.command()
    LOG(f'Command being called is {command}')
    # Commands dict
    commands = {
        'test-module': test_module,
        'cve-search': cve_search,
        'cve-latest': cve_latest,
        'cve': cve
    }
    if command in commands:
        try:
            human_readable, ec, raw_response = commands[command](client, demisto.args())  # type: ignore
            return_outputs(human_readable, ec, raw_response)
        except Exception as err:
            return_error(f'Failed to execute {demisto.command()} command. Error: {str(err)}')
    else:
        raise NotImplementedError(f'{command} is not an existing CVE Search command')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

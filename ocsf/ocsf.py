"""Transforms FDR data to OCSF Format and writes in parquet file and uploads the file to AWS Security Lake"""
import glob
import gzip
import json
import os
import re
import threading
from datetime import datetime
from functools import reduce
from logging import Logger
from filelock import FileLock
import pandas as pd
import yaml

NEWLINE = ord('\n')

CUSTOM_SOURCES = {
    1000: 'CrowdStrike_FILE_ACTIVITY',
    1005: 'CrowdStrike_MODULE_ACTIVITY',
    1007: 'CrowdStrike_PROCESS_ACTIVITY',
    4001: 'CrowdStrike_NETWORK_ACTIVITY',
    4003: 'CrowdStrike_DNS_ACTIVITY'
}

BYTES_IN_MB = 1000000

WRITE_UPLOAD_THREAD_LOCK = threading.Lock()


def upload_parquet_files_to_s3(fdr, s3_target, log_utl: Logger):
    """Uploads parquet files to s3"""
    if fdr.target_bucket_name:
        with WRITE_UPLOAD_THREAD_LOCK:
            for root, _, filenames in os.walk('ext'):
                for filename in filenames:
                    upload_file_path = os.path.join(root, filename)
                    timestamp_str = filename.split('_')[-1].split('.')[0]

                    if not filename.endswith('parquet'):
                        continue

                    if not os.path.exists(upload_file_path):
                        continue

                    if os.path.getsize(upload_file_path) >= (BYTES_IN_MB * fdr.ocsf_max_file_size) or \
                            is_older_than_minutes(timestamp_str, fdr.ocsf_ingest_latency):
                        lock = FileLock(upload_file_path + ".lock")
                        with lock:
                            with open(upload_file_path, 'rb') as parquet_data:
                                log_utl.debug('@@@@uploaded_file@@@@=%s', upload_file_path)
                                s3_target.upload_fileobj(parquet_data, fdr.target_bucket_name, upload_file_path)
                            # Remove the file from the local file system
                            os.remove(upload_file_path)


def is_older_than_minutes(timestamp, minutes):
    """Checks if the timestamp is older than the number of minutes passed

    Arguments:
        timestamp {string} -- timestamp in string format
        minutes {int} -- number of minutes

    Returns:
        bool -- True if the timestamp is older than the number of minutes passed
    """
    return (datetime.utcnow().timestamp() - float(timestamp)) > minutes * 60


def write_to_parquet_file(fdr, ocsf_events, filename_class_uid_key, log_utl: Logger = None):
    """write the events to a parquet file"""
    split_path = filename_class_uid_key.rsplit(os.path.sep, 1)
    log_utl.debug('split_path=%s', split_path)
    folder_path = split_path[0]
    file_name = split_path[1]
    data = pd.DataFrame(ocsf_events)
    data.sort_index(axis=1, inplace=True)
    if 'exit_code' in data.columns:
        data['exit_code'] = data['exit_code'].astype('Int64')
    with WRITE_UPLOAD_THREAD_LOCK:
        file_list = os.listdir(folder_path)
        events_wrote_to_file = False
        if len(file_list) > 0:
            for file_path in file_list:
                parquet_file_name = os.path.join(folder_path, file_path)
                if file_path.endswith('parquet') and file_path.startswith(file_name + '_chunk_') and \
                        os.path.getsize(parquet_file_name) <= (BYTES_IN_MB * fdr.ocsf_max_file_size):
                    lock = FileLock(parquet_file_name + ".lock")
                    with lock:
                        events_wrote_to_file = True
                        log_utl.debug('!!!!!!!!!!Update to bucket=%s, record_len=%s, file_name=%s',
                                      filename_class_uid_key,
                                      len(ocsf_events), parquet_file_name)
                        existing_data = pd.read_parquet(parquet_file_name)
                        existing_data.sort_index(axis=1, inplace=True)
                        concat_data = pd.concat([existing_data, data], axis=0)
                        concat_data.to_parquet(parquet_file_name, compression='gzip', index=False)
        if not events_wrote_to_file:
            parquet_file_name = filename_class_uid_key + '_chunk_' + str(
                int(datetime.utcnow().timestamp())) + '.parquet'
            lock = FileLock(parquet_file_name + ".lock")
            with lock:
                log_utl.debug('#########Write to bucket=%s, record_len=%s, file_name=%s', filename_class_uid_key,
                              len(ocsf_events), parquet_file_name)
                data.to_parquet(parquet_file_name, compression='gzip', index=False)


def read_fdr_part(rdr):
    """reads the fdr file"""
    # to avoid reading the file into memory, we push each byte into a bytearray
    # and yield the completed json once we hit a newline
    tmp = bytearray()
    for char in rdr.read():
        if char == NEWLINE:
            yield json.loads(tmp.decode('utf-8'))
            tmp.clear()
        else:
            tmp.append(char)


def transform_fdr_data_to_ocsf_data(fdr, file, log_utl: Logger = None):
    """Transform FDR data into OSCF format data."""
    total_events_in_file = 0
    mapping_dict_by_name = {}
    supporting_mapping_dict = {}
    for mapping_defn in glob.glob(os.path.join('ocsf', 'mappings', '*.yaml')):
        with open(mapping_defn, encoding='utf-8') as mapping_file:
            mapping_yamls_by_defn_file = yaml.safe_load_all(mapping_file)
            for mapping_yaml in mapping_yamls_by_defn_file:
                mapping_jsons = json.loads(json.dumps(mapping_yaml))
                for mapping_json in mapping_jsons:
                    if mapping_json['type'] == 'Telemetry':
                        prepare_mapping_dict(mapping_json, mapping_dict_by_name)
                    else:
                        prepare_mapping_dict(mapping_json, supporting_mapping_dict)

    file_prefix = 'class_uid'
    ocsf_dicts = {}
    with gzip.open(file, 'rb') as chunk:
        for event in read_fdr_part(chunk):
            total_events_in_file += 1
            mapping_event_simplename = event.get('event_simpleName')
            if mapping_event_simplename in mapping_dict_by_name:
                class_uid_field = next(
                    (field for field in mapping_dict_by_name[mapping_event_simplename].get('fields') if
                     field['name'] == 'class_uid'), False)
                if class_uid_field:
                    class_uid = class_uid_field['value']
                    if class_uid in CUSTOM_SOURCES:
                        timestamp = int(int(event.get('timestamp')) / 1000)
                        folder_path = os.path.join('ext', CUSTOM_SOURCES[class_uid_field['value']],
                                                   'region=' + fdr.target_region_name,
                                                   'accountId=' + fdr.target_account_id,
                                                   'eventHour=' + datetime.fromtimestamp(timestamp).strftime('%Y%m%d%H'))
                        is_dir_exist = os.path.exists(folder_path)
                        if not is_dir_exist:
                            try:
                                os.makedirs(folder_path)
                            except FileExistsError:
                                pass
                        class_uid_path = os.path.join(folder_path, file_prefix + '_' + str(
                            class_uid) + '_part_')
                        ocsf_class_uid_dicts = ocsf_dicts.setdefault(class_uid_path, [])
                        ocsf_dict = {}
                        ocsf_class_uid_dicts.append(
                            transform_event_to_ocsf(event, ocsf_dict, mapping_dict_by_name[mapping_event_simplename],
                                                    supporting_mapping_dict))

    for filename_class_uid_key, values in ocsf_dicts.items():
        event_count = 0
        ocsf_events = []
        for event in values:
            ocsf_events.append(event)
            event_count += 1
            if event_count == 100000:
                write_to_parquet_file(fdr, ocsf_events, filename_class_uid_key, log_utl)
                ocsf_events = []
                event_count = 0

        if len(ocsf_events) > 0:
            write_to_parquet_file(fdr, ocsf_events, filename_class_uid_key, log_utl)

    return total_events_in_file


def prepare_mapping_dict(mapping_json: dict, out_dict: dict):
    """Dict containing the mapping definition for each name"""
    if isinstance(mapping_json.get('name'), list):
        for name in mapping_json.get('name'):
            out_dict[name] = mapping_json
    else:
        out_dict[mapping_json.get('name')] = mapping_json


def transform_event_to_ocsf(event: dict, ocsf_dict: dict, mapping_dict: dict, mapping_supporting_dict: dict):
    """Transforms event to ocsf format"""
    for mapping in mapping_dict.get('mappings'):
        if not event.get(mapping.get('ours')) and mapping.get('default') is not None:
            event[mapping.get('ours')] = mapping.get('default')
        map_field(event, ocsf_dict, mapping, mapping_supporting_dict)
    for field in mapping_dict.get('fields'):
        add_default_field(ocsf_dict, field)

    return dot_notation_to_json(ocsf_dict)


# Transform Functions start #
def extract_filename(value):
    """extracts filename from the value"""
    basename = re.search(r'[^\\/]+(?=[\\/]?$)', value)
    if basename:
        return basename.group(0)
    return value


def as_number(value):
    """converts to int"""
    if value is None:
        return 0
    if '.' in value:
        return int(value.split('.')[0])
    return int(value)


def as_string(value):
    """converts to string"""
    if value is None:
        return ''
    return str(value)


def map_ours_theirs(src: dict, dst: dict, mapping: dict, mapping_supporting_dict: dict):
    # pylint: disable=unused-argument
    """transform function map_ours_theirs"""
    dst[mapping.get('theirs')] = src.get(mapping.get('ours'))


def map_ours_theirs_using_fn(src: dict, dst: dict, mapping: dict, mapping_supporting_dict: dict):
    """transform function map_ours_theirs_using_fn"""
    supporting_enum = mapping_supporting_dict.get(mapping.get('using'))
    for value in supporting_enum.get('values'):
        if value.get('ours') == src.get(mapping.get('ours')):
            dst[mapping.get('theirs')] = value.get('theirs')


def map_ours_theirs_transform_fn(src: dict, dst: dict, mapping: dict, mapping_supporting_dict: dict):
    # pylint: disable=unused-argument
    """transform function map_ours_theirs_transform_fn"""
    transform_fn = ALL_TRANSFORMS.get(mapping.get('transform'))
    dst[mapping.get('theirs')] = transform_fn(src.get(mapping.get('ours')))


def map_items_theirs(src: dict, dst: dict, mapping: dict, mapping_supporting_dict: dict):
    # pylint: disable=unused-argument
    """transform function map_items_theirs"""
    values = []
    for _, item in enumerate(mapping.get('items')):
        value = {}
        for item_mapping in item.get('mappings'):
            if src.get(item_mapping.get('ours')) is not None:
                value[item_mapping.get('theirs')] = src.get(item_mapping.get('ours'))
            for field in item.get('fields'):
                if src.get(item_mapping.get('ours')):
                    value[field.get('name')] = field.get('value')
            values.append(value)

    dst[mapping.get('theirs')] = values


def map_ours_theirs_list(src: dict, dst: dict, mapping: dict, mapping_supporting_dict: dict):
    # pylint: disable=unused-argument
    """transform function map_ours_theirs_list"""
    for their in mapping.get('theirs'):
        if src.get(mapping.get('ours')) is not None:
            dst[their] = src.get(mapping.get('ours'))


def map_ours_theirs_list_using_fn(src: dict, dst: dict, mapping:  dict, mapping_supporting_dict: dict):
    # pylint: disable=unused-argument
    """transform function map_ours_theirs_list_using_fn"""
    supporting_enum = mapping_supporting_dict.get(mapping.get('using'))
    for their in mapping.get('theirs'):
        if src.get(mapping.get('ours')) is not None:
            for value in supporting_enum.get('values'):
                if value.get('ours') == src.get(mapping.get('ours')):
                    dst[their] = value.get(mapping.get('theirs'))


def map_ours_theirs_list_transform_fn(src: dict, dst: dict, mapping: dict, mapping_supporting_dict: dict):
    # pylint: disable=unused-argument
    """transform function map_ours_theirs_list_transform_fn"""
    transform_fn = ALL_TRANSFORMS.get(mapping.get('transform'))
    for their in mapping.get('theirs'):
        if src.get(mapping.get('ours')) is not None:
            dst[their] = transform_fn(src.get(mapping.get('ours')))


# Transform Functions End#
def apply_transform(src: dict, mapping: dict):
    """determines the transform function to be applied"""
    ours = mapping.get('ours')
    theirs = mapping.get('theirs')
    optional_using = mapping.get('using')
    optional_translate = mapping.get('transform')
    optional_items = mapping.get('items')
    return_func = ''
    if ours and not isinstance(ours, list):
        if theirs and not isinstance(theirs, list):
            if src.get(ours) is not None and not optional_translate and not optional_using and not optional_items:
                return_func = 'map_ours_theirs'
            elif src.get(ours) is not None and not optional_translate and optional_using and not optional_items:
                return_func = 'map_ours_theirs_using_fn'
            elif src.get(ours) is not None and optional_translate and not optional_using and not optional_items:
                return_func = 'map_ours_theirs_transform_fn'
        if theirs and isinstance(theirs, list):
            if not optional_translate and not optional_using and not optional_items:
                return_func = 'map_ours_theirs_list'
            elif not optional_translate and optional_using and not optional_items:
                return_func = 'map_ours_theirs_list_using_fn'
            elif optional_translate and not optional_using and not optional_items:
                return_func = 'map_ours_theirs_list_transform_fn'
    elif not ours and optional_items and isinstance(optional_items, list):
        if theirs and not isinstance(theirs, list) and not optional_translate and not optional_using:
            return_func = 'map_items_theirs'

    return return_func


def map_field(src: dict, dst: dict, mapping: dict, mapping_supporting_dict: dict):
    """maps the FDR field to OCSF field"""
    map_fn = ALL_TRANSFORMS.get(apply_transform(src, mapping))
    if map_fn:
        map_fn(src, dst, mapping, mapping_supporting_dict)


def dot_notation_to_json(ocsf_dict):
    """converts the dot notations in the json to nested json"""
    output = {}
    for key, value in ocsf_dict.items():
        path = key.split('.')
        target = reduce(lambda d, k: d.setdefault(k, {}), path[:-1], output)
        target[path[-1]] = value
    return output


def add_default_field(dest: dict, field: dict):
    """adds the default field in the dict"""
    name = field.get('name')
    value = field.get('value')
    if isinstance(value, list) and len(value) == 1 and value[0] is None:
        dest[name] = []
    else:
        dest[name] = value


ALL_TRANSFORMS = {
    'extract_filename': extract_filename,
    'as_number': as_number,
    'as_string': as_string,
    'map_ours_theirs': map_ours_theirs,
    'map_ours_theirs_using_fn': map_ours_theirs_using_fn,
    'map_ours_theirs_transform_fn': map_ours_theirs_transform_fn,
    'map_items_theirs': map_items_theirs,
    'map_ours_theirs_list': map_ours_theirs_list,
    'map_ours_theirs_list_using_fn': map_ours_theirs_list_using_fn,
    'map_ours_theirs_list_transform_fn': map_ours_theirs_list_transform_fn
}

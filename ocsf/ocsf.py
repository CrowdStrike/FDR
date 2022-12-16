import glob
import gzip
import json
import os
import re
from datetime import datetime
from functools import reduce
from filelock import FileLock
import pandas as pd
from logging import Logger
import yaml
import threading

NEWLINE = ord('\n')

CUSTOM_SOURCES = {
    1000: 'CrowdStrike_FILE_ACTIVITY',
    1005: 'CrowdStrike_MODULE_ACTIVITY',
    1007: 'CrowdStrike_PROCESS_ACTIVITY',
    4001: 'CrowdStrike_NETWORK_ACTIVITY',
    4003: 'CrowdStrike_DNS_ACTIVITY'
}

MAX_FILE_SIZE_BYTES = 2.24e+8

WRITE_UPLOAD_THREAD_LOCK = threading.Lock()


def upload_parquet_files_to_s3(fdr, s3_target, log_utl: Logger):
    if fdr.target_bucket_name:
        with WRITE_UPLOAD_THREAD_LOCK:
            for root, directories, filenames in os.walk('ext'):
                for filename in filenames:
                    upload_file_path = os.path.join(root, filename)
                    if filename.endswith('parquet') and \
                            os.path.exists(upload_file_path) and \
                            os.path.getsize(upload_file_path) >= MAX_FILE_SIZE_BYTES:
                        lock = FileLock(upload_file_path + ".lock")
                        with lock:
                            with open(upload_file_path, 'rb') as parquet_data:
                                log_utl.debug('@@@@uploaded_file@@@@=%s', upload_file_path)
                                s3_target.upload_fileobj(parquet_data, fdr.target_bucket_name, upload_file_path)
                            # Remove the file from the local file system
                            os.remove(upload_file_path)


def get_bucket_path(ts):
    """5-minute window bucket based on class_uid_path"""
    bucket = int(datetime.fromtimestamp(ts).minute / 5)
    return str(bucket)


def write_to_parquet_file(ocsf_events, filename_class_uid_key, log_utl: Logger = None):
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
                        os.path.getsize(parquet_file_name) <= MAX_FILE_SIZE_BYTES:
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
    # to avoid reading the file into memory, we push each byte into a bytearray
    # and yield the completed json once we hit a newline
    tmp = bytearray()
    for c in rdr.read():
        if c == NEWLINE:
            yield json.loads(tmp.decode('utf-8'))
            tmp.clear()
        else:
            tmp.append(c)


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
            if mapping_event_simplename in mapping_dict_by_name.keys():
                class_uid_field = next(
                    (field for field in mapping_dict_by_name[mapping_event_simplename].get('fields') if
                     field['name'] == 'class_uid'), False)
                if class_uid_field:
                    class_uid = class_uid_field['value']
                    if class_uid in CUSTOM_SOURCES.keys():
                        ts = int(int(event.get('timestamp')) / 1000)
                        folder_path = os.path.join('ext', CUSTOM_SOURCES[class_uid_field['value']],
                                                   'region=' + fdr.target_region_name,
                                                   'accountId=' + fdr.target_account_id,
                                                   'eventHour=' + datetime.fromtimestamp(ts).strftime('%Y%m%d%H'))
                        is_dir_exist = os.path.exists(folder_path)
                        if not is_dir_exist:
                            try:
                                os.makedirs(folder_path)
                            except FileExistsError:
                                pass
                        class_uid_path = os.path.join(folder_path, file_prefix + '_' + str(
                            class_uid) + '_part_' + get_bucket_path(ts))
                        ocsf_class_uid_dicts = ocsf_dicts.setdefault(class_uid_path, [])
                        ocsf_dict = {}
                        ocsf_class_uid_dicts.append(
                            transform_event_to_ocsf(event, ocsf_dict, mapping_dict_by_name[mapping_event_simplename],
                                                    supporting_mapping_dict))

    for filename_class_uid_key in ocsf_dicts:
        event_count = 0
        ocsf_events = []
        for event in ocsf_dicts[filename_class_uid_key]:
            ocsf_events.append(event)
            event_count += 1
            if event_count == 100000:
                write_to_parquet_file(ocsf_events, filename_class_uid_key, log_utl)
                ocsf_events = []
                event_count = 0

        if len(ocsf_events) > 0:
            write_to_parquet_file(ocsf_events, filename_class_uid_key, log_utl)

    return total_events_in_file


def prepare_mapping_dict(mapping_json: dict, out_dict: dict):
    if isinstance(mapping_json.get('name'), list):
        for name in mapping_json.get('name'):
            out_dict[name] = mapping_json
    else:
        out_dict[mapping_json.get('name')] = mapping_json


def transform_event_to_ocsf(event: dict, ocsf_dict: dict, mapping_dict: dict, mapping_supporting_dict: dict):
    for mapping in mapping_dict.get('mappings'):
        map_field(event, ocsf_dict, mapping, mapping_supporting_dict)
    for field in mapping_dict.get('fields'):
        add_default_field(ocsf_dict, field)

    return dot_notation_to_json(ocsf_dict)


# Transform Functions start #
def extract_filename(value):
    basename = re.search(r'[^\\/]+(?=[\\/]?$)', value)
    if basename:
        return basename.group(0)


def as_number(value):
    if value is None:
        return 0
    elif '.' in value:
        return int(value.split('.')[0])
    else:
        return int(value)


def map_ours_theirs(src: dict, dst: dict, mapping: dict, mapping_supporting_dict: dict):
    dst[mapping.get('theirs')] = src.get(mapping.get('ours'))


def map_ours_theirs_using_fn(src: dict, dst: dict, mapping: dict, mapping_supporting_dict: dict):
    supporting_enum = mapping_supporting_dict.get(mapping.get('using'))
    for value in supporting_enum.get('values'):
        if value.get('ours') == src.get(mapping.get('ours')):
            dst[mapping.get('theirs')] = value.get(mapping.get('theirs'))


def map_ours_theirs_transform_fn(src: dict, dst: dict, mapping: dict, mapping_supporting_dict: dict):
    transform_fn = ALL_TRANSFORMS.get(mapping.get('transform'))
    dst[mapping.get('theirs')] = transform_fn(src.get(mapping.get('ours')))


def map_items_theirs(src: dict, dst: dict, mapping: dict, mapping_supporting_dict: dict):
    values = []
    for idx, item in enumerate(mapping.get('items')):
        value = {}
        for item_mapping in item.get('mappings'):
            if src.get(item_mapping.get('ours')):
                value[item_mapping.get('theirs')] = src.get(item_mapping.get('ours'))
        for field in item.get('fields'):
            if src.get(item_mapping.get('ours')):
                value[field.get('name')] = field.get('value')
        values.append(value)

    dst[mapping.get('theirs')] = values


def map_ours_theirs_list(src: dict, dst: dict, mapping: dict, mapping_supporting_dict: dict):
    for their in mapping.get('theirs'):
        if src.get(mapping.get('ours')):
            dst[their] = src.get(mapping.get('ours'))


def map_ours_theirs_list_using_fn(src: dict, dst: dict, mapping: dict, mapping_supporting_dict: dict):
    supporting_enum = mapping_supporting_dict.get(mapping.get('using'))
    for their in mapping.get('theirs'):
        if src.get(mapping.get('ours')):
            for value in supporting_enum.get('values'):
                if value.get('ours') == src.get(mapping.get('ours')):
                    dst[their] = value.get(mapping.get('theirs'))


def map_ours_theirs_list_transform_fn(src: dict, dst: dict, mapping: dict, mapping_supporting_dict: dict):
    transform_fn = ALL_TRANSFORMS.get(mapping.get('transform'))
    for their in mapping.get('theirs'):
        if src.get(mapping.get('ours')):
            dst[their] = transform_fn(src.get(mapping.get('ours')))


# Transform Functions End#
def apply_transform(src: dict, dst: dict, mapping: dict):
    ours = mapping.get('ours')
    theirs = mapping.get('theirs')
    optional_using = mapping.get('using')
    optional_translate = mapping.get('transform')
    optional_items = mapping.get('items')

    if ours and not isinstance(ours, list) and src.get(ours) and theirs and not isinstance(
            theirs, list) and not optional_translate and not optional_using and not optional_items:
        return 'map_ours_theirs'
    elif ours and not isinstance(ours, list) and src.get(ours) and theirs and not isinstance(
            theirs, list) and not optional_translate and optional_using and not optional_items:
        return 'map_ours_theirs_using_fn'
    elif ours and not isinstance(ours, list) and src.get(ours) and theirs and not isinstance(
            theirs, list) and optional_translate and not optional_using and not optional_items:
        return 'map_ours_theirs_transform_fn'
    elif not ours and optional_items and type(optional_items) is list and theirs and not isinstance(
            theirs, list) and not optional_translate and not optional_using:
        return 'map_items_theirs'
    elif ours and not isinstance(ours, list) and theirs and isinstance(
            theirs, list) and not optional_translate and not optional_using and not optional_items:
        return 'map_ours_theirs_list'
    elif ours and not isinstance(ours, list) and theirs and isinstance(
            theirs, list) and not optional_translate and optional_using and not optional_items:
        return 'map_ours_theirs_list_using_fn'
    elif ours and not isinstance(ours, list) and theirs and isinstance(
            theirs, list) and optional_translate and not optional_using and not optional_items:
        return 'map_ours_theirs_list_transform_fn'


def map_field(src: dict, dst: dict, mapping: dict, mapping_supporting_dict: dict):
    map_fn = ALL_TRANSFORMS.get(apply_transform(src, dst, mapping))
    if map_fn:
        map_fn(src, dst, mapping, mapping_supporting_dict)


def dot_notation_to_json(a):
    output = {}
    for key, value in a.items():
        path = key.split('.')
        target = reduce(lambda d, k: d.setdefault(k, {}), path[:-1], output)
        target[path[-1]] = value
    return output


def add_default_field(dest: dict, field: dict):
    name = field.get('name')
    value = field.get('value')
    if isinstance(value, list) and len(value) == 1 and value[0] is None:
        dest[name] = []
    else:
        dest[name] = value


ALL_TRANSFORMS = {
    'extract_filename': extract_filename,
    'as_number': as_number,
    'map_ours_theirs': map_ours_theirs,
    'map_ours_theirs_using_fn': map_ours_theirs_using_fn,
    'map_ours_theirs_transform_fn': map_ours_theirs_transform_fn,
    'map_items_theirs': map_items_theirs,
    'map_ours_theirs_list': map_ours_theirs_list,
    'map_ours_theirs_list_using_fn': map_ours_theirs_list_using_fn,
    'map_ours_theirs_list_transform_fn': map_ours_theirs_list_transform_fn
}
"""Unit test for ../slips.py"""
from ..slips import *
import os
import argparse
import subprocess
import time
import pytest

IS_IN_A_DOCKER_CONTAINER = os.environ.get('IS_IN_A_DOCKER_CONTAINER', False)


def do_nothing(*args):
    """Used to override the print function because using the self.print causes broken pipes"""
    pass


# Main Class tests


def create_Main_instance():
    """returns an instance of Main() class in slips.py"""
    return Main()


def test_load_modules():
    main = create_Main_instance()
    failed_to_load_modules = main.load_modules(
        ['template', 'mldetection-1', 'ensembling']
    )[1]
    assert failed_to_load_modules == 0


#
# @pytest.mark.skipif(IS_IN_A_DOCKER_CONTAINER, reason='This functionality is not supported in docker')
# def test_save():
#     """ tests saving the database"""
#     # this test needs sudo
#     command = f'sudo ./slips.py -l -f dataset/sample_zeek_files -s > /dev/null 2>&1'
#     # this function returns when slips is done
#     os.system(command)
#     assert os.path.exists('redis_backups/sample_zeek_files.rdb')
#     os.remove('redis_backups/sample_zeek_files.rdb')
#
# @pytest.mark.skipif(IS_IN_A_DOCKER_CONTAINER, reason='This functionality is not supported in docker')
# def test_load(database):
#     """ tests loading the database"""
#     # make sure the db exists
#     if not os.path.exists('redis_backups/sample_zeek_files.rdb'):
#         # save it if it doesn't exist
#         command = f'sudo ./slips.py -l -f dataset/sample_zeek_files -s > /dev/null 2>&1'
#         os.system(command)
#
#     # this test needs sudo
#     command = f'sudo ./slips.py -d redis_backups/sample_zeek_files.rdb  > /dev/null 2>&1'
#     # this function returns when slips is done
#     os.system(command)
#     # wait for the command to finish
#     time.sleep(3)
#     # check a random value to make sure the db is loaded
#     x = database.r.hgetall('profile_10.0.2.2_timewindow1_flows')
#     assert 'CDm47v3jrYL8lx0cOh' in str(x)


def test_recognize_host_ip():
    main = create_Main_instance()
    assert main.recognize_host_ip() != None


def test_create_folder_for_logs():
    main = create_Main_instance()
    assert main.create_folder_for_logs() != False


def test_check_redis_database():
    main = create_Main_instance()
    assert main.check_redis_database() == True


def test_clear_redis_cache_database():
    main = create_Main_instance()
    assert main.clear_redis_cache_database() == True


def test_check_zeek_or_bro():
    main = create_Main_instance()
    assert main.check_zeek_or_bro() != False


# Daemon tests
@pytest.mark.skipif(
    os.geteuid() != 0, reason='supported only with root priveledges'
)
def create_Daemon_instance():
    """returns an instance of Daemon() class in slips.py"""
    slips = create_Main_instance()
    # since we wont becalling __main__ we need to setup the args manually
    slips.args = argparse.Namespace(
        blocking=False,
        clearcache=False,
        config='slips.conf',
        debug=None,
        filepath='dataset/hide-and-seek-short.pcap',
        gui=False,
        interactive=False,
        interface=None,
        nologfiles=True,
        output='output/',
        pcapfilter=None,
        restartdaemon=False,
        stopdaemon=False,
        verbose=None,
    )
    return Daemon(slips)


@pytest.mark.skipif(
    os.geteuid() != 0, reason='supported only with root priveledges'
)
def test_setup_std_streams():
    daemon = create_Daemon_instance()
    os.system('./slips.py -f dataset/hide-and-seek-short.pcap')
    # __init__ calls read_configuration which calls setup_std_streams
    # we need to make sure that all files are there
    assert os.path.exists(daemon.logsfile)
    assert os.path.exists(daemon.stdout)
    assert os.path.exists(daemon.stderr)
    assert os.path.exists(daemon.stdin)
    assert os.path.exists(daemon.pidfile)
    # make sure the files aren't empty
    with open(daemon.logsfile, 'r') as logsfile:
        # make sure used file are logged
        used_files = f'Logsfile: {daemon.logsfile}\npidfile:{daemon.pidfile}\nstdin : {daemon.stdin}\nstdout: {daemon.stdout}\nstderr: {daemon.stderr}\n'
        assert used_files in logsfile.read()
    # stop the daemon
    os.system('sudo ./slips.py -S')


@pytest.mark.skipif(
    os.geteuid() != 0, reason='supported only with root priveledges'
)
def test_pidfile():
    """tests creating, writing to and deleting pidfile"""
    # run slips in a parallel process
    cmd = './slips.py -c slips.conf -l -f dataset/hide-and-seek-short.pcap'
    subprocess.Popen([cmd], shell=True, stdin=None, stdout=None, stderr=None)
    # wait until the pid is written to the file
    time.sleep(2)
    # this instance is just to get the pidfile, we're not starting the daemon again
    daemon = create_Daemon_instance()
    # make sure there's a pid in pidfile
    assert os.stat(daemon.pidfile).st_size > 0
    # # wait for slips to finish
    # time.sleep(30)
    # stop slips
    os.system('sudo ./slips.py -S')
    # make sure the pidfile is deleted after slips is finished
    assert not os.path.exists(daemon.pidfile)


@pytest.mark.skipif(
    os.geteuid() != 0, reason='supported only with root priveledges'
)
def test_print():
    daemon = create_Daemon_instance()
    daemon.print('Test')
    with open(daemon.logsfile, 'r') as f:
        assert 'Test' in f.read()


@pytest.mark.skipif(
    os.geteuid() != 0, reason='supported only with root priveledges'
)
def test_stop():
    """tests if the daemon is successfully killed after running the daemon stop function"""
    # run slips in a parallel process
    cmd = (
        'sudo ./slips.py -c slips.conf -l -f dataset/hide-and-seek-short.pcap'
    )
    subprocess.Popen([cmd], shell=True, stdin=None, stdout=None, stderr=None)
    # wait until the pid is written to the file
    time.sleep(2)
    # this instance is just to get the pidfile, we're not starting the daemon again
    daemon = create_Daemon_instance()
    # get the pid of the daemon
    with open(daemon.pidfile, 'r') as f:
        pid = int(f.read())
    # run the daemon stop function
    os.system('sudo ./slips.py -S')
    # assert that pid is not there after stopping
    process_killed = False
    try:
        os.kill(pid, 0)
        process_killed = True
    except OSError as e:
        if str(e).find('No such process') > 0:
            # some error occured
            process_killed = True
    assert process_killed

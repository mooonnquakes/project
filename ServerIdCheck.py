import os
import time
import pymysql
import datetime
import argparse
import itertools
import subprocess
import concurrent.futures
from base import mysql_cfg
from collections import defaultdict


def GetOptions():
    usage = '''
        python3 $0 -t type -r id

        示例：更新检测
        python3 ServerIdCheck.py -t update -r 1:2:3:4:5:6_10
    '''
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument('-r', '--IdRange', dest='IdRange', required=True, type=str)
    parser.add_argument('-t', '--type', dest='type', required=True, type=str)
    option = parser.parse_args()
    return option

def CheckOpenDB(obj):
    host = ''
    port = 3306
    user = 'ht'
    passwd = ''
    StatusSql = f'select server_id, status, is_private from ht_rd_admin.rd_server where server_id in ({obj}) and status !=3;'

    connection = pymysql.connect(host=host, port=port, user=user, password=passwd, db='ht_rd_admin', charset='utf8')
    cursor = connection.cursor()
    try:
        cursor.execute(StatusSql)
        connection.commit()
    except Exception:
        connection.rollback()
    connection.close()
    return cursor.fetchall()

def ConnMysql(SQL):
    connection = pymysql.connect(host=DBHost, port=DBPort, user=DBUser, password=DBPassword,
                                 db=DBName, charset='utf8')
    cursor = connection.cursor()
    try:
        cursor.execute(SQL)
        connection.commit()
    except Exception as err:
        connection.rollback()
    connection.close()
    return cursor.fetchall()

def GetServStatus(ip, cmd):
    execCommond = f'ssh -p8822 root@{ip} "{cmd}"'
    rc = subprocess.Popen(execCommond, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    out, err = rc.communicate()
    tmp_res = out.splitlines()
    res = {int(serv.split('_')[1]): f'{serv.split("_")[0]} {num}' for serv, num in (item.split(' ') for item in tmp_res)}
    return res, err

def ListToRange(obj):
    res = []
    obj = sorted(set(obj))
    for key, group in itertools.groupby(enumerate(obj), lambda t: t[1] - t[0]):
        group = list(group)
        res.append(['%s_%s' % (group[0][1], group[-1][1]), str(group[-1][1])][group[0][1] == group[-1][1]])
    return ':'.join(res)

def RangeToList(obj):
    res = []
    obj = [i for i in obj.split(':')]
    for i in obj:
        tmp = i.split('_')
        op = list(map(int, tmp))
        res.extend(list(range(min(op), max(op)+1)))
    return res

def GetLanIp(obj):
    res = {}
    obj = str(obj).strip('[]')
    sql = f'select private_ip,server_id from {DBName}.{TableName} where server_id in ({obj}) and status !=3;'
    SqlRes = list(map(lambda x: {x[1]: x[0]}, ConnMysql(sql)))
    for i in SqlRes: res.update(i)
    return res

class CheckMaster:
    def __init__(self, type, obj):
        self.OPType = type
        self.ObjRange = obj
        tmpObjList = RangeToList(self.ObjRange)
        # obj where status !=3
        strObj = str(tmpObjList).strip('[]')
        getSql = f'select server_id from {DBName}.{TableName} where server_id in ({strObj}) and status !=3;'
        resObj = ConnMysql(getSql)
        self.ObjList = sum(list(map(list, resObj)), [])

        self.StartServId = []
        self.Today = datetime.datetime.now().strftime('%Y-%m-%d')
        self.writeTime = datetime.datetime.now().strftime('%H:%M:%S')

    def LogInit(self):
        OPPath = os.path.join(RunLogPath, self.Today)
        if not os.path.exists(OPPath):
            try:
                os.makedirs(OPPath)
            except Exception:
                pass
        self.OPLogFile = os.path.join(OPPath)
        GetCName = f'select channel from {DBName}.{TableName} where server_id={self.ObjList[0]}'
        self.CName = ConnMysql(GetCName)[0][0]
        self.writeFile = os.path.join(self.OPLogFile, f'{self.OPType}-{self.CName}-{self.ObjList[0]}---{self.writeTime}.check-log')

    def WriteLog(self, level, msg):
        WTime = datetime.datetime.now().strftime('%H:%M:%S')
        WData = f'{WTime} [{level}]\t {msg}\n'
        print(WData, end='')
        fobj = open(self.writeFile, 'a')
        fobj.writelines(WData)
        fobj.close()
        return WData

    def ExistId(self):
        get_all_server = f'select server_id from {DBName}.{TableName} where status !=3;'
        result = ConnMysql(get_all_server)
        all_servId = sum(list(map(list, result)), [])
        ExistId_res = list(set(self.ObjList).difference(all_servId))
        if ExistId_res:
            for i in ExistId_res: self.ObjList.remove(i)
        self.WriteLog('info', f'不存在id: {ListToRange(ExistId_res)}')

    def CheckOpen(self):
        running = []
        obj = ','.join(str(x) for x in self.ObjList)
        check_id = CheckOpenDB(obj)
        check_func = lambda r: r[1] == 1 and r[2] == 0
        try:
            for r in check_id:
                if check_func(r): running.append(r[0])
        except TypeError:
            if check_func(check_id): running.append(check_id[0])
        self.WriteLog('info', f'对外开放的服：{ListToRange(running)}')

    def CheckStart(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            err_id = []
            threads = []
            ThreadsRes = []
            start_list = []
            conformity = defaultdict(list)
            result_dict = {}
            get_LanIp = GetLanIp(self.ObjList)

            for sid, ip in get_LanIp.items(): conformity[ip].append(sid)

            for remote_ip in conformity:
                tmp_sids = conformity[remote_ip]
                sids = [tmp_sids[0], ":".join(map(str, tmp_sids))][len(tmp_sids) > 1]

                cmd = f'cd /data/scripts/ && bash check_server_status.sh {sids}'
                future = executor.submit(GetServStatus, remote_ip, cmd)
                threads.append(future)

            for future in concurrent.futures.as_completed(threads): ThreadsRes.append(future.result())

            for v in ThreadsRes:
                val = v[0]
                result_dict.update(val)

            for ite in result_dict.items():
                if ite[1]:
                    serv_type, serv_num = ite[1].split(' ')
                    valid_conditions = {'global': '5', 'game': '4', 'cross': '3'}

                    if serv_type in valid_conditions and serv_num == valid_conditions[serv_type]:
                        start_list.append(ite[0])
                    else:
                        err_id.append(ite[0])
                else:
                    err_id.append(ite[0])

        self.WriteLog('info', '启动的服：%s' % ListToRange(start_list))
        self.WriteLog('info', '异常的服：%s' % ListToRange(err_id))

    def CheckChannel(self):
        obj = str(self.ObjList).strip('[]')
        sql = f'select distinct channel from {DBName}.{TableName} where server_id in ({obj}) and status !=3;'
        result_sql = ConnMysql(sql)
        self.TCName = sum(list(map(list, result_sql)), [])
        self.WriteLog('info', f'此次操作涉及到的所有渠道名：{self.TCName}')

    def PChannelInfo(self):
        self.WriteLog('info', '********************')
        self.WriteLog('info', '具体渠道id信息:')
        for c in self.TCName:
            self.WriteLog('info', '********************')
            self.WriteLog('info', '渠道：%s' % c)
            sql = f'select server_id from {DBName}.{TableName} where channel=\'{c}\' and status !=3;'
            ChannelSId = ConnMysql(sql)
            CSidList = sum(list(map(list, ChannelSId)), [])
            OPOBJ = list(set(CSidList).intersection(set(self.ObjList)))
            self.WriteLog('info', f'将操作id：{ListToRange(OPOBJ)}')
            NoExtId = list(set(CSidList).difference(self.ObjList))
            self.WriteLog('info', f'未操作id：{ListToRange(NoExtId)}')

    def ForgetGame(self):
        obj = ','.join(str(i) for i in self.ObjList)
        getGame = f"select distinct server_id from {DBName}.{TableName} where cross_id in ({','.join(str(i) for i in {obj})}) and type=\'game\' and status !=3;"
        game_result = ConnMysql(getGame)
        all_game = [i[0] for i in game_result]
        Fgame = list(set(all_game) - set(self.ObjList))
        self.WriteLog('info', '')
        self.WriteLog('info', f'可能遗漏的游服：{ListToRange(Fgame)}')

    def ForgetCross(self):
        obj = str(self.ObjList).strip('[]')
        sql = f'select cross_id from {DBName}.{TableName} where server_id in ({obj}) and type=\'game\' and status !=3;'
        result_all_cross = ConnMysql(sql)
        all_cross = sum(list(map(list, result_all_cross)), [])
        FgCross = list(set(all_cross).difference(set(self.ObjList)))
        self.WriteLog('info', f'可能遗漏的跨服：{ListToRange(FgCross)}')

    def ForgetGlobal(self):
        obj = str(self.ObjList).strip('[]')
        sql = f'select global_id from {DBName}.{TableName} where server_id in ({obj}) and type=\'game\' and status !=3;'
        result_all_global = ConnMysql(sql)
        all_global = sum(list(map(list, result_all_global)), [])
        FgGlobal = list(set(all_global).difference(set(self.ObjList)))
        self.WriteLog('info', f'可能遗漏的公共服：{ListToRange(FgGlobal)}')
        self.WriteLog('info', '注: 该工具仅供辅助检查id参考，不做为最终结果，最终id结果需由运营确认！！！')

    def MasterRun(self):
        RunTime = time.time()
        self.LogInit()
        self.ExistId()
        self.CheckOpen()
        self.CheckStart()
        self.CheckChannel()
        self.PChannelInfo()
        self.ForgetGame()
        self.ForgetCross()
        self.ForgetGlobal()
        EndTime = time.time()
        ExecTime = EndTime - RunTime
        self.WriteLog('info', '耗时：%.2fs' % ExecTime)


if __name__ == '__main__':
    DBUser = mysql_cfg['user']
    DBHost = mysql_cfg['host']
    DBPort = mysql_cfg['port']
    DBPassword = mysql_cfg['passwd']
    DBName = "game_manage"
    TableName = 'game'
    RunLogPath = '/data/log/cmdb_log/checkId'

    option = GetOptions()
    OPType = option.type
    ObjRange = option.IdRange
    Run = CheckMaster(OPType, ObjRange)
    Run.MasterRun()

#分析使用的易受攻击的第三方库（TPL）的情况，使用的第三方库里用了哪些危险权限，扫出库里使用的API，再去看有无使用危险权限的API，利用LibScan

import os
from collections import defaultdict
import yaml
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from androguard.misc import AnalyzeAPK, Analysis
import json
import subprocess
import re
import spacy
nlp = spacy.load("en_core_web_md")
# from utils import __de

def decompile(apk_path):
    print("start consistency analyse")
    a, df, dx = AnalyzeAPK(apk_path)  # 输出的分别是a: 一个APK对象、d:一个DalvikVMFormat对象数组和dx：Analysis对象。
    # self.__apk: apk.APK = a  # apk 文件对象，其实就是读取 AndroidManifest.xml 文件, 了解过Android 的程序员应该知道，这个文件中就是清仓文件， 我们申请一些权限，注册 Activity, Service, Broadcast,ContentProvader 都在清仓文件中申请。
    # self.__df = df  # 解析出方法调用图
    # self.__dx: Analysis = dx  # 我们可以使用 dex 对象， 获取文件中所有类的，所有方法，所有的成员变量和字符串。注意， 这边获取的 dex 对象是一个 list
    return a,df,dx

class TPL_permission_analysis:

    @staticmethod
    def start(apk_path):
        instance = TPL_permission_analysis()
        # instance.__decompile(apk_path)
        # instance.__search_vulnerable_tpl(apk_path)  #检测是否包含易受攻击的TPL，直接生成文档
        
        # instance.__search_general_tpl(apk_path)
        # instance.__generate_general_tpl_results(apk_path)
        instance.__tpl_permission_analysis()
        
        # consistency_result = instance.__search_sensitive_policy(appname,pii_usage_function_list)
        # instance.__generate_results(consistency_result,appname)


    def __init__(self):
        os.mkdir('../result/lib_result')
		pass

    

    def __search_vulnerable_tpl(self,apk_path):
        libscan_path = '../LibScan/tool/LibScan.py'
        params = ['python',
                  libscan_path,
                  'detect_all',
                  '-o',
                  '../result/lib_result/vulnerable_lib',
                  '-af',
                  os.path.split(apk_path)[0],
                  '-lf',
                  '../vulnerability_libs',
                  '-ld',
                  '../vulnerability_libs_dex'
                  ]
        # os.system(' '.join(params))
        process = subprocess.Popen(params,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        _, stderr = process.communicate()
        if len(stderr) > 0:
            print(str(stderr))
        
    # def __generate_vulnerable_tpl_results(self):
        # TPL_app = []    #存在vulnerble TPL的app
        # TPL_num = defaultdict(int) #key是vulnerble TPL,value是出现该TPL的app的数目
        # for root,dirs,files in os.walk("/data12T/guohy/Metadetector/lib_result/vulnerable_lib"):
            # for file in files:
                # with open(os.path.join(root,file),'r') as f:
                    # text = f.readlines()
                    # if len(text) != 1:
                        # TPL_app.append(file)
                    # else:
                        # continue
                    # for line in text:
                        # if 'lib:' in line:
                            # tpl = line.split('lib:')[-1]
                            # TPL_num[tpl] += 1
        # print(TPL_app)
        # print(TPL_num)
        
    def __search_general_tpl(self,apk_path):
        libscan_path = '../LibScan/tool/LibScan.py'
        category = os.path.split(apk_path)[-2].split('/')[-1] #判断是一开始的200个，之后的300个，还是最后新增的400个apk
        params = ['python',
                  libscan_path,
                  'detect_all',
                  '-o',
                  '../lib_result/general_lib',
                  '-af',
                  os.path.split(apk_path)[0],
                  '-lf',
                  '../general_libs_include_ase',
                  '-ld',
                  '../general_libs_include_ase_dex'
                  ]
        process = subprocess.Popen(params,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        _, stderr = process.communicate()
        if len(stderr) > 0:
            print(str(stderr))

    def __generate_general_tpl_results(self,apk_path):
        general_TPL_app = []    #存在vulnerble TPL的app
        general_TPL_num = defaultdict(int) #key是vulnerble TPL,value是出现该TPL的app的数目
        for root,dirs,files in os.walk("/data12T/guohy/Metadetector/lib_result/vulnerable_lib"):
            for file in files:
                with open(os.path.join(root,file),'r') as f:
                    text = f.readlines()
                    if len(text) != 1:
                        general_TPL_app.append(file)
                    else:
                        continue
                    for line in text:
                        if 'lib:' in line:
                            tpl = line.split('lib:')[-1]
                            general_TPL_num[tpl] += 1
        print(general_TPL_app)
        print(general_TPL_num)
        
    def __tpl_permission_analysis(self):    
        # category = os.path.split(apk_path)[-2]
        # app_name = os.path.split(apk_path)[-1]
		os.mkdir('../lib_result/general_lib_permission')
        with open('../sdk-29-mapping.json','r') as f:
            mm = f.readline()
            dalvik_permission = json.loads(mm)
        lib_classes = {'android/support/annotation':'support-annotations',   #mapping between TPL and package name
                       'javax/inject':'javax-inject',
                       'com/google/common':'guava',
                       'javax/annotation':'jsr305',
                       'com/google/gson':'gson',
                       'com/fasterxml/jackson':'FasterXML-Jackson-Core',
                       'dagger':'dagger',
                       'org/slf4j/impl':'slf4j-android'
                       }
        for root,dirs,files in os.walk("../lib_result/general_lib"):
            for file in files:
                with open(os.path.join(root,file),'r') as f:
                    text = f.readlines()
                    if len(text) == 1:
                        continue
                    general_lib = []
                    for line in text:
                        if 'lib:' in line:
                            general_lib.append(line.split('lib:')[-1].strip())
                    apk_path = '../App_list/'+root.split('/')[-1]+'/'+file.replace('.txt','')
                    a,df,dx = decompile(apk_path)
                    lib_permission = defaultdict(list) #第三方库存在哪些权限
                    # for lib in general_lib:
                        # lib = lib.lower()
                    class_names = []
                    for cls in df:
                        for method in cls.get_methods():
                            if method.get_class_name() not in class_names:
                                class_names.append(method.get_class_name())
                                print(method.get_class_name())
                            for lib_class in lib_classes:
                                if lib_class in method.get_class_name():    #找到该函数属于的某个关键类
                                    print(method.get_descriptor())
                                    for descriptor in dalvik_permission:
                                        if method.get_descriptor() == descriptor:
                                            lib_permission[lib_classes[lib_class]].extend(dalvik_permission[descriptor])
                                    if 'external' in method.get_descriptor().lower() and 'write' in method.get_descriptor().lower():
                                        if 'WRITE_EXTERNAL_STORAGE' not in lib_permission[lib_classes[lib_class]]:
                                            lib_permission[lib_classes[lib_class]].append('WRITE_EXTERNAL_STORAGE')
                                    if 'external' in method.get_descriptor().lower() and 'read' in method.get_descriptor().lower():
                                        if 'READ_EXTERNAL_STORAGE' not in lib_permission[lib_classes[lib_class]]:
                                            lib_permission[lib_classes[lib_class]].append('READ_EXTERNAL_STORAGE')
                                    if 'audio' in method.get_descriptor().lower():
                                        if 'AUDIO' not in lib_permission[lib_classes[lib_class]]:
                                            lib_permission[lib_classes[lib_class]].append('AUDIO')
                                    if 'bluetooth' in method.get_descriptor().lower():
                                        if 'BLUETOOTH' not in lib_permission[lib_classes[lib_class]]:
                                            lib_permission[lib_classes[lib_class]].append('BLUETOOTH')
                                    if 'wake' in method.get_descriptor().lower() and 'lock' in method.get_descriptor().lower():
                                        if 'WAKE_LOCK' not in lib_permission[lib_classes[lib_class]]:
                                            lib_permission[lib_classes[lib_class]].append('WAKE_LOCK')
                    
                with open('../lib_result/general_lib_permission/{}'.format(file),'w') as g:
                    g.write(json.dumps(lib_permission))




                    
      









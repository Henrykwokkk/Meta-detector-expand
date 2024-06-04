import os
from langdetect import detect
import collections

def is_english(text):
    try:
        return detect(text) == 'en'
    except:
        return False

def review_amount_analysis():
    permission_keywords = ['account access','account',
                        'bluetooth','bluetooth device',
                        'read calender','calendar','write calendar',
                        'read contact data','write contact','contact',
                        'location','track','gps',
                        'mail','voicemail',
                        'picture','photo','media','file','take picture','taking picture','camera',
                        'sms','receive mms','send mms','read mms','message','read message','mms','receive sms',
                        'network','network state','wifi information','wifi','internet access','internet','network connect',
                        'notification','system alert window','system alert',
                        # 'phone call','phone number','outgoing call','manage call','phone state','call','call log','call\'s log','log','sip',
                        'sensor data','sensor','fingerprint','nfc','vibrate',
                        'package size','install shortcut','delete package','battery info','recorder task','boot','boot complete','wap push','run in background','root',
                        'write storage','storage','read storage','sd card','file',
                        'mircophone',
                        'permission','access','intrusive','identity','personal info','malware','virus','malicious',
                        'hand','eye','body','face','track','biometric','iris']   #biometric keywords

    app_reviews_mapping = {} #key是app名，value是所有的review
    app_target_review_mapping = collections.defaultdict(list) #key是app名，value是包含keyword的review
    review_num = 0
    target_review_num = 0   #包含目标keyword的所有review数目
    os.mkdir('./900_apps_review')
	os.mkdir('./900_apps_review_privacy')
	path = './900_apps_review'
    privacy_path = './900_apps_review_privacy'
    for root, dirs, files in os.walk(path):
        for app_name in files:
            file_path = os.path.join(root,app_name)
            privacy_file_path = os.path.join(privacy_path,app_name)
            with open(file_path,'r') as f,open(privacy_file_path,'w') as g:
                review_texts = f.readlines()
                # review_num += len(review_texts)
                app_reviews_mapping[app_name] = review_texts
                for review_text in review_texts:
                    review_text = review_text.strip().lower()
                    if not is_english(review_text):
                        continue
                    if review_text == '':
                        continue
                    review_num += 1
                    for keyword in permission_keywords:
                        if keyword in review_text:
                            target_review_num += 1
                            app_target_review_mapping[app_name].append(review_text)
                            g.write(review_text)
                            g.write('\n')
                            break
    print(review_num)
    print(target_review_num)
                
def permission_review_analysis():
    permission_keywords = ['account access','account',
                        'bluetooth','bluetooth device',
                        'read calender','calendar','write calendar',
                        'read contact data','write contact','contact',
                        'location','track','gps',
                        'mail','voicemail',
                        'picture','photo','media','file','take picture','taking picture','camera','mircophone',
                        'sms','receive mms','send mms','read mms','message','read message','mms','receive sms',
                        'network','network state','wifi information','wifi','internet access','internet','network connect',
                        'notification','system alert window','system alert',
                        # 'phone call','phone number','outgoing call','manage call','phone state','call','call log','call\'s log','log','sip',
                        'sensor data','sensor','fingerprint','nfc','vibrate',
                        'package size','install shortcut','delete package','battery info','recorder task','boot','boot complete','wap push','run in background','root',
                        'write storage','storage','read storage','sd card','file',
                        'permission','access','intrusive','identity','personal info','malware','virus','malicious',
                        'hand','eye','body','face','track','biometric','iris']   #biometric keywords


    permission_review_mapping = {'account':[],'bluetooth':[],'calendar':[],'contact':[],'location':[],'mail':[],'media':[],'messages':[],'network':[],'notification':[],'phone':[],'sensor':[],'system':[],'storage':[],'general':[],'biometric':[]}
    for root, dirs, files in os.walk('/data12T/guohy/Metadetector/ReviewAnalysis/900_apps_review_privacy'):
        for file in files:
            file_path = os.path.join(root,file)
            with open(file_path,'r') as f:
                review_texts = f.readlines()
                for text in review_texts:
                    for keyword in permission_keywords:
                        if keyword in text:
                            if keyword in ['account access','account'] and text not in permission_review_mapping['account']:
                                permission_review_mapping['account'].append(text)
                            if keyword in ['bluetooth','bluetooth device'] and text not in permission_review_mapping['bluetooth']:
                                permission_review_mapping['bluetooth'].append(text)
                            if keyword in ['read calender','calendar','write calendar'] and text not in permission_review_mapping['calendar']:
                                permission_review_mapping['calendar'].append(text)
                            if keyword in ['read contact data','write contact','contact'] and text not in permission_review_mapping['contact']:
                                permission_review_mapping['contact'].append(text)
                            if keyword in ['location','track','gps'] and text not in permission_review_mapping['location']:
                                permission_review_mapping['location'].append(text)
                            if keyword in ['mail','voicemail'] and text not in permission_review_mapping['mail']:
                                permission_review_mapping['mail'].append(text)
                            if keyword in ['picture','photo','media','file','take picture','taking picture','camera','mircophone'] and text not in permission_review_mapping['media']:
                                permission_review_mapping['media'].append(text)
                            if keyword in ['sms','receive mms','send mms','read mms','message','read message','mms','receive sms'] and text not in permission_review_mapping['messages']:
                                permission_review_mapping['messages'].append(text)
                            if keyword in ['network','network state','wifi information','wifi','internet access','internet','network connect'] and text not in permission_review_mapping['network']:
                                permission_review_mapping['network'].append(text)
                            if keyword in ['notification','system alert window','system alert'] and text not in permission_review_mapping['notification']:
                                permission_review_mapping['notification'].append(text)
                            # if keyword in ['phone call','phone number','outgoing call','manage call','phone state','call','call log','call\'s log','log','sip'] and text not in permission_review_mapping['phone']:
                                # permission_review_mapping['phone'].append(text)    
                            if keyword in ['sensor data','sensor','fingerprint','nfc','vibrate'] and text not in permission_review_mapping['sensor']:
                                permission_review_mapping['sensor'].append(text)
                            if keyword in ['package size','install shortcut','delete package','battery info','recorder task','boot','boot complete','wap push','run in background','root'] and text not in permission_review_mapping['system']:
                                permission_review_mapping['system'].append(text)
                            if keyword in ['write storage','storage','read storage','sd card','file'] and text not in permission_review_mapping['storage']:
                                permission_review_mapping['storage'].append(text)
                            if keyword in ['permission','access','intrusive','identity','personal info','malware','virus','malicious'] and text not in permission_review_mapping['general']:
                                permission_review_mapping['general'].append(text)
                            if keyword in ['hand','eye','body','face','track','biometric','iris'] and text not in permission_review_mapping['biometric']:
                                permission_review_mapping['biometric'].append(text)
    print(permission_review_mapping)

def review_distribution():
    general_review_distribution = collections.defaultdict(int)  #key是review数目，value是app数目
    privacy_review_distribution = collections.defaultdict(int)
    for root, dirs, files in os.walk('/data12T/guohy/Metadetector/ReviewAnalysis/900_apps_review'):
        for file in files:
            file_path = os.path.join(root,file)
            with open(file_path,'r') as f:
                review_texts = f.readlines()
                review_num = 0
                for review_text in review_texts:
                    review_text = review_text.strip().lower()
                    if not is_english(review_text):
                        continue
                    if review_text == '':
                        continue
                    review_num += 1
                general_review_distribution[review_num] += 1
    for root, dirs, files in os.walk('/data12T/guohy/Metadetector/ReviewAnalysis/900_apps_review_privacy'):
        for file in files:
            file_path = os.path.join(root,file)
            with open(file_path,'r') as f:
                review_texts = f.readlines()
                privacy_review_distribution[len(review_texts)] += 1
    
    print(general_review_distribution)
    sorted_dict = dict(sorted(general_review_distribution.items()))
    print(privacy_review_distribution)
    sorted_dict = dict(sorted(privacy_review_distribution.items()))
    print(sorted_dict)



review_amount_analysis()
permission_review_analysis()
review_distribution()

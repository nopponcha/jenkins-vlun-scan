# Jenkins Vulnerability Scan

สคริปต์ตรวจช่องโหว่ของ Jenkins core และ plugin โดยเทียบเวอร์ชันที่ติดตั้งกับ **Security Warnings ทางการ** จาก Jenkins Update Center
(`https://updates.jenkins.io/update-center.actual.json` → array `warnings`) แล้วสร้างรายงานให้ส่ง DevOps ได้ทันที

## ไฟล์
| ไฟล์ | หน้าที่ |
|---|---|
| `scan.py` | สคริปต์หลัก (Python 3, ใช้แค่ stdlib) |
| `Jenkinsfile` | Pipeline รันทุกสัปดาห์ |
| `mock_jenkins.py` | Mock server สำหรับทดสอบ |
| `plugins.txt.example` | ตัวอย่างไฟล์รายชื่อ plugin |

## วิธีทำงาน
1. อ่านเวอร์ชัน core จาก header `X-Jenkins` (ผู้ใช้ทั่วไปที่มีสิทธิ์ Overall/Read ก็อ่านได้) และบอกว่าเป็น **LTS** (เช่น 2.462.3) หรือ **weekly** (เช่น 2.480)
2. อ่านรายการ plugin จาก `/pluginManager/api/json?depth=1` — **ต้องมีสิทธิ์ Overall/SystemRead หรือ Administer**
   - ถ้าได้ 403 สคริปต์จะแจ้งเตือนชัดเจนในรายงาน แล้ว **สแกนเฉพาะ core ต่อ**
   - หรือใช้ `--plugins-file` กับไฟล์ที่ admin export ให้ (ดูด้านล่าง)
3. โหลด Update Center (weekly) และ `stable/` (LTS) เพื่อหาเวอร์ชันแนะนำ
4. จับคู่เวอร์ชันกับ regex `versions[].pattern` ของแต่ละ warning
5. สร้าง `scan-output/report.json`, `report.html`, `summary.md` และตารางใน console

## ขั้นตอนติดตั้ง
1. **สร้าง API token**: คลิกชื่อผู้ใช้ (มุมขวาบน) → *Security* (หรือ *Configure*) → *API Token* → *Add new Token* → คัดลอกเก็บไว้
2. **สร้าง Credential**: *Manage Jenkins → Credentials* → เลือก domain → *Add Credentials* → ชนิด **Username with password**
   Username = ชื่อผู้ใช้, Password = API token, **ID = `jenkins-api-token`**
   (ถ้าไม่มีสิทธิ์เข้า Manage Jenkins ให้สร้างที่ระดับ Folder ของคุณ หรือขอ DevOps สร้างให้)
3. **สร้าง Job**: *New Item → Pipeline* → *Pipeline script from SCM* ชี้ไปยัง repo ที่มีไฟล์ชุดนี้ (Script Path = `Jenkinsfile`)
   agent ต้องมี `python3`
4. (ไม่บังคับ) ติดตั้ง plugin **HTML Publisher** เพื่อดูรายงานในหน้า build และ **Email Extension** เพื่อส่งเมลหา DevOps (เปิดพารามิเตอร์ `NOTIFY_DEVOPS`)

## สิทธิ์ที่แนะนำให้ขอ DevOps
ขอสิทธิ์ **Overall/SystemRead** (อ่านอย่างเดียว ไม่ใช่ admin) ให้กับบัญชีที่ใช้สแกน
— ต้องเปิดใช้ด้วย system property `-Djenkins.security.SystemReadPermission=true` (หรือใช้ plugin *Extended Read Permission*) แล้วกำหนดใน Matrix/Role-based Authorization

## ถ้าไม่มีสิทธิ์: ให้ DevOps export รายชื่อ plugin
**วิธีที่ 1 – Script Console** (*Manage Jenkins → Script Console*):
```groovy
Jenkins.instance.pluginManager.plugins.sort{it.shortName}.each{ println "${it.shortName}:${it.version}" }
```
คัดลอกผลลัพธ์เป็น `plugins.txt`

**วิธีที่ 2 – curl (admin)**:
```bash
curl -s -u admin:API_TOKEN "https://jenkins.example.com/pluginManager/api/json?depth=1&tree=plugins[shortName,longName,version,active,hasUpdate]" -o plugins.json
```
จากนั้นรัน: `python3 scan.py --plugins-file plugins.txt` (รองรับทั้ง `.txt` แบบ `name:version` และ `.json`) หรือใส่ path ในพารามิเตอร์ `PLUGINS_FILE` ของ job

## การใช้งานแบบ manual
```bash
export JENKINS_URL=https://jenkins.example.com JENKINS_USER=me JENKINS_TOKEN=xxxx
python3 scan.py --fail-on-vuln               # exit 2 ถ้าเจอช่องโหว่
python3 scan.py --insecure                    # ข้ามการตรวจ TLS (self-signed cert)
python3 scan.py --update-center ./uc.json --update-center-stable ''   # ใช้ไฟล์ offline
```
ไฟล์ offline: `curl -o uc.json https://updates.jenkins.io/update-center.actual.json`

Exit code: `0` ปกติ, `2` เจอช่องโหว่ (เมื่อใช้ `--fail-on-vuln`), อื่นๆ = error — ใน Jenkinsfile exit 2 จะทำให้ build เป็น **UNSTABLE**

## อ่านรายงานอย่างไร
- **Severity**: ประเมินจากข้อความ advisory (CRITICAL = RCE/sandbox bypass/rogue release, HIGH = XSS/CSRF/credentials/permission) — ระดับ CVSS จริงดูในลิงก์ advisory
- **Current / Recommended**: เวอร์ชันปัจจุบัน และเวอร์ชันล่าสุดใน Update Center (core LTS แนะนำ LTS ล่าสุด)
- **Advisory**: ลิงก์ไปหน้า Jenkins Security Advisory
- **Plugins with updates**: plugin ที่มีเวอร์ชันใหม่ แม้ยังไม่มีช่องโหว่
- `summary.md`: ส่งให้ DevOps ได้ทันที (Slack/Email/Ticket)

## หมายเหตุ
Jenkins มี **Administrative Monitor ในตัว** ที่แสดงคำเตือนความปลอดภัย (ไอคอนโล่/ระฆังมุมขวาบน และหน้า *Manage Jenkins*) จากข้อมูลชุดเดียวกัน แต่ admin เท่านั้นที่เห็น — สคริปต์นี้ช่วยให้ทีม dev ตรวจเองและเก็บประวัติรายสัปดาห์ได้
ใช้กับ Jenkins ที่คุณได้รับอนุญาตเท่านั้น

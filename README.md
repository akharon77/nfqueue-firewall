# nfqueue-firewall

Правила обрабатываются по порядку. Конфиг в формате ALLOW/DENY DNSRR/DNSQR, после указать поле и значение.

Для DNSRR:
 - rrname
 - type
 - rdata

Для DNSQR:
 - qname
 - qtype

Запуск скрипта: `python run.py <config> <queue-num>`


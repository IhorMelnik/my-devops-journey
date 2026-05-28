
# 🚀 Ultimate DevOps Cheat Sheet

Збірник основних команд, скриптів та трюків для щоденної роботи DevOps-інженера. Збережіть собі, щоб не шукати в документації.

---

## 📁 Зміст
- [🐙 Git & GitHub](#-git--github)
- [🐳 Docker & Docker Compose](#-docker--docker-compose)
- [☸️ Kubernetes (kubectl)](#-kubernetes-kubectl)
- [🏗️ Terraform](#️-terraform)
- [🤖 Ansible](#-ansible)
- [🐧 Linux, Мережа & Діагностика](#-linux-мережа--діагностика)
- [🔄 CI/CD Пайплайни](#-cicd-пайплайни)

---

## 🐙 Git & GitHub

### Очищення репозиторію
```bash
git clean -fd          # Видалити всі невідстежувані файли та папки
git fetch --prune      # Видалити посилання на гілки, яких уже немає в remote
```

### Робота з коммитами
```bash
git commit --amend -m "Нове повідомлення"  # Змінити повідомлення останнього комміту
git reset --soft HEAD~1                   # Скасувати комміт, але залишити зміни в коді
```

### Пошук та виправлення
```bash
git blame <file_name>                     # Подивитися, хто і коли міняв рядки у файлі
git cherry-pick <commit_hash>             # Перенести конкретний комміт в поточну гілку
```

---

## 🐳 Docker & Docker Compose

### Очищення простору (Команда на кожен день)
```bash
docker system prune -a --volumes # Видалити ВСІ неактивні контейнери, мережі, образи та томи
```

### Налагодження та логування
```bash
docker exec -it <container_id> sh  # Увійти всередину контейнера (або /bin/bash)
docker logs -f --tail 100 <id>     # Дивитися останні 100 рядків логів у реальному часі
docker inspect <container_id>      # Показати повну конфігурацію (IP, монтування, змінні)
```

### Docker Compose
```bash
docker compose up -d --build       # Перезбирати образи та запустити контейнери у фоні
docker compose ps                  # Перевірити статус сервісів у поточному проекті
docker compose down -v             # Зупинити проект та повністю видалити його томи (volumes)
```

---

## ☸️ Kubernetes (kubectl)

### Навігація та контекст
```bash
kubectl config use-context <context-name>                         # Змінити кластер
kubectl config set-context --current --namespace=<namespace-name> # Змінити namespace за замовчуванням
```

### Діагностика та логи pod-ів
```bash
kubectl get pods -n <namespace> -w                        # Стежити за статусом подів у реальному часі
kubectl logs -f <pod-name> -n <namespace>                 # Стрімити логи пода
kubectl exec -it <pod-name> -n <namespace> -- /bin/sh     # Зайти всередину контейнера в поді
kubectl describe pod <pod-name> -n <namespace>            # Подивитися деталі та помилки (Events)
kubectl get events --sort-by='.metadata.creationTimestamp' # Показати останні події в кластері
```

### Керування ресурсами
```bash
kubectl rollout restart deployment/<name> -n <namespace>  # Безпечно перезапустити Deployment
kubectl scale deployment/<name> --replicas=3 -n <namespace> # Змінити кількість реплік
```

---

## 🏗️ Terraform

### Базовий робочий процес
```bash
terraform init          # Ініціалізувати плагіни та бекенд
terraform validate      # Перевірити синтаксис конфігураційних файлів
terraform plan -out=tfplan # Створити план змін та зберегти його у файл
terraform apply tfplan  # Застосувати збережений план (швидко і безпечно)
```

### Ручне керування State-файлом
```bash
terraform state list                      # Вивести список усіх ресурсів у поточному state
terraform state rm <resource_address>     # Видалити ресурс із файлу стану (не видаляючи в хмарі)
terraform import <resource_address> <id>  # Додати існуючий у хмарі ресурс до вашого стану
```

---

## 🤖 Ansible

### Перевірка зв'язку та запуск ad-hoc команд
```bash
ansible all -m ping -i inventory.ini                   # Перевірити доступність усіх хостів
ansible webservers -m shell -a "uptime" -i inventory.ini # Виконати швидку команду на групі серверів
```

### Робота з Playbooks
```bash
ansible-playbook site.yml -i inventory.ini --check     # Запустити плейбук у режимі тестування (dry-run)
ansible-playbook site.yml -i inventory.ini --tags "nginx" # Запустити тільки завдання з певним тегом
```

---

## 🐧 Linux, Мережа & Діагностика

### Моніторинг ресурсів
```bash
df -h                    # Вільне місце на дисках у зручному форматі
du -sh * | sort -hr      # Показати топ папок, які займають найбільше місця
free -m                  # Статус оперативної пам'яті в мегабайтах
htop                     # Інтерактивна утиліта для моніторингу процесів (CPU/RAM)
```

### Мережеві команди
```bash
ss -tulnp                # Показати всі відкриті порти та процеси, що їх використовують
curl -Iv https://example.com # Перевірити SSL-сертифікат, швидкість з'єднання та заголовки
nc -zv <IP> <PORT>       # Швидко перевірити, чи відкритий конкретний порт на сервері
ip a                     # Подивитися мережеві інтерфейси та IP-адреси
```

---

## 🔄 CI/CD Пайплайни

### Пропуск збірки (Універсально для GitHub/GitLab)
Додайте `[skip ci]` або `[ci skip]` у текст повідомлення комміту. Пайплайн для цього пушу не запуститься, що економить час та гроші.

### Налагодження змінних в пайплайні
Якщо крок падає через брак змінних оточення, додайте тимчасовий крок для їх перевірки:
```yaml
- name: Debug Env Variables
  run: env | sort
```
*(Увага: видаліть цей крок після налагодження, щоб не "світити" секрети в логах!)*

---

💡 **Порада щодо розширення:** Додавайте сюди свої кастомні bash-скрипти та специфічні команди для хмарних провайдерів (AWS, GCP, Azure), які ви використовуєте на проектах.
# anpr-system

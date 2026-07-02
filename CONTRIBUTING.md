# Contribuyendo a SuperReconn

¡Gracias por tu interés en contribuir a SuperReconn! Este documento proporciona pautas y procedimientos para colaborar en el proyecto.

## 📋 Tabla de Contenidos

1. [Código de Conducta](#código-de-conducta)
2. [Cómo Reportar Bugs](#cómo-reportar-bugs)
3. [Cómo Proponer Features](#cómo-proponer-features)
4. [Guía de Desarrollo](#guía-de-desarrollo)
5. [Estándares de Código](#estándares-de-código)
6. [Proceso de Pull Request](#proceso-de-pull-request)

---

## Código de Conducta

Este proyecto adhiere a un código de conducta que esperamos que todos los participantes respeten:

- **Respeto:** Trata a todos con respeto y dignidad
- **Inclusión:** Bienvenemos contribuyentes de todas las orígenes y experiencias
- **Profesionalismo:** Mantén las discusiones técnicas y constructivas
- **Privacidad:** Respeta la privacidad de otros usuarios y datos

---

## Cómo Reportar Bugs

Si encuentras un bug en SuperReconn, por favor abre un Issue en GitHub con la siguiente información:

### Información Requerida

```markdown
## Descripción del Bug
[Descripción clara del problema]

## Pasos para Reproducir
1. Ejecutar comando: `python3 SuperReconn.py example.com ...`
2. Observar error: `[Error aquí]`

## Comportamiento Esperado
[Qué debería ocurrir]

## Comportamiento Actual
[Qué ocurre actualmente]

## Información del Sistema
- OS: [Ubuntu 22.04 / Debian 11 / macOS / etc]
- Python: [3.8 / 3.9 / 3.10 / 3.11]
- Versión de SuperReconn: [1.0.0 o rama/commit]
- Herramientas críticas:
  - massdns: [versión o N/A]
  - httpx: [versión o N/A]
  - naabu: [versión o N/A]
  - nmap: [versión o N/A]

## Logs y Archivos
[Adjunta execution.log o fragmentos relevantes]

## Contexto Adicional
[Cualquier información que ayude a reproducir el problema]
```

### Antes de Reportar

- Verifica que el bug no haya sido reportado ya
- Prueba con la última versión del código
- Lee la sección de Troubleshooting en README.md
- Intenta reproducir con las opciones por defecto

---

## Cómo Proponer Features

Para sugerir una nueva feature, abre un Issue con el siguiente formato:

```markdown
## Descripción
[Descripción clara de la feature]

## Justificación
[Por qué es útil / problema que resuelve]

## Ejemplos de Uso
[Cómo se usaría la feature]

## Complejidad Estimada
- [ ] Baja (< 1 día)
- [ ] Media (1-3 días)
- [ ] Alta (> 3 días)

## Dependencias
[Herramientas, librerías o cambios en BD que requiere]

## Alternativas Consideradas
[Otras formas de resolver el problema]
```

### Criterios para Aceptar Features

- **Utilidad:** ¿Es útil para la mayoría de usuarios?
- **Scope:** ¿Está dentro del alcance del proyecto?
- **Mantenimiento:** ¿Es realista mantenerla a largo plazo?
- **Compatibilidad:** ¿Rompe cambios existentes?

---

## Guía de Desarrollo

### Setup de Desarrollo

```bash
# Clonar repositorio
git clone https://github.com/tuusuario/SuperReconn.git
cd SuperReconn

# Ejecutar setup automatizado
chmod +x setup.sh
./setup.sh --dev

# Activar entorno virtual
source venv/bin/activate

# Cargar variables de entorno
source .env

# Verificar que todo funciona
python3 SuperReconn.py --help
```

### Estructura de Branches

```
main                 # Rama de producción (estable)
├─ develop          # Rama de desarrollo (pre-release)
│  ├─ feature/*      # Nuevas features
│  └─ bugfix/*       # Fixes de bugs
```

### Crear una Feature

```bash
# 1. Actualizar código local
git checkout develop
git pull origin develop

# 2. Crear rama de feature
git checkout -b feature/mi-nueva-feature

# 3. Hacer cambios y commits
git add .
git commit -m "feat: descripción clara del cambio"

# 4. Push a repositorio
git push origin feature/mi-nueva-feature

# 5. Crear Pull Request desde GitHub
```

### Testing Local

```bash
# Ejecutar tests
pytest tests/ -v

# Con coverage
pytest tests/ --cov=SuperReconn --cov-report=html
open htmlcov/index.html

# Test específico
pytest tests/test_SuperReconn.py::test_normalize_domain -v

# Test un dominio pequeño
python3 SuperReconn.py example.com --no-nuclei --no-crawl

# Test con flags específicos
python3 SuperReconn.py example.com --no-waf --only-check
```

---

## Estándares de Código

### Python Style Guide (PEP 8)

```python
# ✅ CORRECTO
def process_results(
    domains: List[str],
    *,
    timeout: int = 30,
    retry: bool = True
) -> Dict[str, Any]:
    """Procesa resultados del scan."""
    results = {}
    for domain in domains:
        if validate_domain(domain):
            results[domain] = get_info(domain, timeout=timeout)
    return results


# ❌ INCORRECTO
def process_results(domains,timeout=30,retry=True):
    results = {}
    for d in domains:
        results[d] = get_info(d)
    return results
```

### Convenciones Importantes

- **Nombres:** `snake_case` para funciones/variables, `PascalCase` para clases
- **Docstrings:** Usa docstrings en formato Google/NumPy para todas las funciones públicas
- **Type Hints:** Siempre incluye type hints
- **Línea máxima:** 100 caracteres (flexible hasta 120 para URLs)
- **Comentarios:** Usa comentarios para el "por qué", no para el "qué"

### Validación Automática

```bash
# Formatear código con Black
black SuperReconn.py persist_mssql.py

# Verificar linting
flake8 SuperReconn.py --max-line-length=120

# Verificar tipos
mypy SuperReconn.py --strict

# Todo en uno
make lint
```

---

## Proceso de Pull Request

### Antes de Hacer el PR

1. **Update de branches:**
   ```bash
   git fetch origin
   git rebase origin/develop
   ```

2. **Tests locales:**
   ```bash
   pytest tests/ -v
   python3 SuperReconn.py example.com --no-nuclei --no-crawl
   ```

3. **Linting:**
   ```bash
   make lint
   ```

4. **Commits limpios:**
   ```bash
   # Todos los commits deben ser significativos
   git log origin/develop..HEAD --oneline
   ```

### Formato del PR

```markdown
## Descripción
[Descripción clara del cambio]

## Tipo de Cambio
- [ ] Bug fix
- [ ] Nueva feature
- [ ] Mejora de documentación
- [ ] Refactoring
- [ ] Cambio en dependencias

## Relacionado con Issue
Closes #123

## Cambios Realizados
- [x] Implementé funcionalidad X
- [x] Agregué tests para Y
- [x] Actualicé documentación

## Testing
- [ ] He testado localmente
- [ ] Agregué tests nuevos
- [ ] Los tests existentes pasan

## Checklist
- [ ] Mi código sigue el estilo del proyecto
- [ ] He actualizado la documentación
- [ ] No tengo conflictos con `develop`
- [ ] No rompo cambios existentes
```

### Revisión de PR

Los PRs serán revisados por maintainers. Por favor:

- **Responde a feedback:** Si hay comentarios, implementa cambios o discute
- **Sé paciente:** La revisión puede tomar tiempo
- **Mantén actualizado:** Si hay conflictos, rebase en `develop`

---

## Convenciones de Commits

Usamos [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Tipos de Commit

- `feat:` Nueva feature
- `fix:` Bug fix
- `docs:` Cambios en documentación
- `style:` Formateo de código (sin cambios funcionales)
- `refactor:` Reorganización de código
- `perf:` Mejoras de performance
- `test:` Agregar o modificar tests
- `chore:` Dependencias, configuración

### Ejemplos

```
feat(nuclei): agregar categoría de DNS templates
fix(massdns): resolver timeout en resolvers largos
docs(readme): agregar sección de troubleshooting
test(SuperReconn): agregar tests para normalize_domain
```

---

## Reportes de Seguridad

⚠️ **IMPORTANTE:** Si encuentras una vulnerabilidad de seguridad:

1. **NO** abras un Issue público
2. Envía un email privado a: [security@example.com]
3. Incluye: descripción, pasos para reproducir, impacto potencial

---

## Preguntas o Necesitas Ayuda?

- 📖 Lee el [README.md](README.md)
- 💬 Abre una [Discussion](https://github.com/tuusuario/SuperReconn/discussions)
- 🐛 Busca [Issues existentes](https://github.com/tuusuario/SuperReconn/issues)
- 📞 Contáctanos en Discord/Slack

---

## Licencia

Al contribuir a SuperReconn, aceptas que tus contribuciones se licencien bajo la misma licencia MIT del proyecto.

---

Gracias por contribuir a SuperReconn! 🙌

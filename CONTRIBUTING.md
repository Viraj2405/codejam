# Contributing to Scaleway Audit Sentinel

Thank you for your interest in contributing!

## Development Setup

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/your-username/audit-sentinel.git
   cd audit-sentinel
   ```

2. **Set up environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Install dependencies**
   ```bash
   make deps
   make install-tools
   ```

4. **Start services**
   ```bash
   make dev
   ```

5. **Run migrations**
   ```bash
   make migrate-up
   ```

## Code Style

- Follow Go standard formatting (`go fmt`)
- Run linter before committing (`make lint`)
- Write tests for new features
- Update documentation as needed

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes
3. Add/update tests
4. Ensure all tests pass (`make test`)
5. Update documentation if needed
6. Submit pull request with clear description

## Testing

- Write unit tests for new functions
- Add integration tests for API endpoints
- Ensure test coverage doesn't decrease

## Commit Messages

Use clear, descriptive commit messages:
- `feat: add impossible travel detection rule`
- `fix: correct IP address parsing`
- `docs: update API documentation`


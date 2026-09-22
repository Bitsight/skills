# AI Madrid Skills

A collection of AI skills for the Madrid platform. These skills are bundled together with skills from [ai-customer-skills](https://gitlab.com/colorprinter/common/ai/ai-customer-skills) and distributed publicly via the [Bitsight Skills GitHub repository](https://github.com/Bitsight/skills).

## Skills

- **bitsight-generate-spm-insights** - Generate supply chain management insights from Bitsight data

## Important Notes

### Submodule Integration
This repository is integrated as a submodule (`skills-public`) in the [ai-customer-skills](https://gitlab.com/colorprinter/common/ai/ai-customer-skills) repository.

**When making changes here**, you must update the submodule in `ai-customer-skills` for the changes to be reflected in the bundled skills package:

```bash
cd ai-customer-skills
git submodule update --remote skills-public
git add skills-public
git commit -m "Update skills-public submodule"
git push origin <branch>
```

### Public Distribution
⚠️ **Important**: Any changes merged to the `main` branch of this repository will be **publicly displayed** in the [Bitsight Skills GitHub repository](https://github.com/Bitsight/skills).

Ensure all code, documentation, and assets meet public distribution standards before merging.

## Development Workflow

1. Create a feature branch for your skill changes
2. Implement and test your changes
3. Create a merge request to `main`
4. Once merged, the skill will be automatically bundled and pushed to the public GitHub repository
5. Update the submodule in `ai-customer-skills` to reflect the changes

## Building & Distribution

Skills in this repository are:
- Packaged individually as `.zip` files
- Bundled with `ai-customer-skills` into `bitsight-agent-skills.zip`
- Published to AWS S3
- Synced to the public [Bitsight Skills GitHub repository](https://github.com/Bitsight/skills)

## Related Repositories

- [ai-customer-skills](https://gitlab.com/colorprinter/common/ai/ai-customer-skills) - Main skills repository (bundled with this)
- [Bitsight Skills (Public)](https://github.com/Bitsight/skills) - Public distribution of all skills

# CLAUDE.md
This file provides information that Claude Code needs to know when handling the source code of Kaede.

## Overview
Kaede is a Python library for processing HTTP requests and responses.

It supports HTTP/1.1/2/3 and can handle requests and responses based on structures such as Request/Response inspired by ASGI.

## Automated Testing
pytest is used for automated testing. While minimal tests can be covered by automated tests, they are not perfect, so prioritize manual testing as much as possible.

When using automated tests or updating test content, observe the following:

- Use automated tests only to easily verify that all existing features in Kaede function correctly and are in full compliance with specifications such as RFCs.
- The content of automated tests must always verify whether it is in full compliance with the strict protocol specifications, regardless of Kaede's current behavior.
    - If you assume Kaede's current behavior, the automated tests may pass even when there is an error in the implementation, preventing early detection.
    - If automated tests are based on current behavior, they effectively become tests for verifying consistency with the status quo, which defeats their original purpose.
    - If an implementation error is discovered and fixed, tests will not pass if they were based on the previous behavior, even if the fix itself is correct. This increases the effort required to update test content and undermines reliability.
    - For the reasons mentioned above, when updating test content, do not trust Kaede's source code or behavior at all; ensure the content complies with actual protocol specifications. You should follow this for safety and quality, even if you wrote the code yourself and are confident in its compliance.

## Testing by Claude
When performing manual testing, follow these steps:

1. First, discover as many bugs or vulnerabilities as possible. Use various creative methods such as reading all the code, carefully examining each part of the code, executing the server, or testing in different environments like Docker. Focus only on finding as many issues as possible without confirming whether they are actually problems.
2. Next, create a detailed list of the issues discovered in step 1.
3. Finally, verify whether those issues are truly problems. Use various methods such as reading related code, thinking through the actual execution flow line by line, verifying in a real environment, or checking the actual specifications of related libraries on the internet.

### Note
This procedure incorporates the following approaches. Please keep these in mind when updating this procedure:
- Dividing into multiple steps helps focus on each stage, enabling more reliable testing.
- Step 2 is performed before verifying issues, which helps in better understanding through documentation, making the verification and correction of issues easier and more reliable.

## Fixing by Claude
When fixing issues, follow these steps:

1. First, verify whether the issue is actually a problem. Use various methods such as reading related code, thinking through the actual execution flow line by line, verifying in a real environment, or checking the actual specifications of related libraries on the internet. Even if a pre-check was performed as in step 3 of "Testing by Claude," you must perform this again.
2. Next, gather the information necessary for the fix. As in step 1, read the actual code and conduct research on the internet.
3. Finally, fix the issue in compliance with the rules for code changes in the "Changes by Claude" section.

## Changes by Claude
When making changes to code or content, observe the following:

- Maintain the structure and style of existing code, and use simple and reliable methods to implement features or fix issues with highly readable code.
- Strive to ensure that each feature or module does not contain code specific to other features, modules, or common areas. If there is absolutely no way other than adding it, keep the added code to a minimum.
- Carefully consider implementation methods. In particular, pay close attention to safety and reliability.
- It must be possible for humans to understand the changes completely and without misunderstanding. Provide detailed work logs in a prominent form at a medium frequency during work.
- When implementing new features, add as many high-quality and detailed tests as possible to the automated tests. When adding, strictly observe the rules for expanding test items.
- Always run tests after completing work. Execute automated tests with pytest or the steps in the "Testing by Claude" section. It is strongly recommended to perform manual testing compliant with the "Testing by Claude" section in addition to automated tests.

When approved by human review and a human requests the creation of a commit, you may create a commit after observing the following:

- Before actually creating the commit, summarize the commit message and the changes to be included (i.e., staged with git add) in detail, inform the human, and create the commit once approved.
- Write the commit message in Japanese or English.
- The first line of the commit message should allow for easy understanding of the commit content even without knowing the details in the following lines.
- Summarize more detailed changes from the second/third line onwards.
- Add the "Claude: " prefix to the first line of the commit message.
- Include a trailer in the format "Assisted-by: AGENT_NAME:MODEL_VERSION [TOOL 0] [TOOL 1]" in the commit.
    - Use names like "Claude", "ChatGPT", or "Gemini" for AGENT_NAME.
    - Use text like "claude-sonnet-4.6" for MODEL_VERSION.
    - For [TOOL 0] [TOOL 1], list the names of the tools used to analyze the code, separated by spaces.
        - You do not need to list basic daily system tools like file editing, web search/browsing, git, uv, or clang.

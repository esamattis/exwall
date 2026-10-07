import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

/** The JSON rule document exchanged with the mocked REST API. */
interface RulesDocument {
    revision: string;
    rules: { index: number | null; fields: Record<string, unknown> }[];
}

/** Mock every API request, recording saves and failing unexpected endpoints locally. */
async function mockApi(
    page: Page,
    document: RulesDocument,
    saveError?: { status: number; error: string },
) {
    const saves: RulesDocument[] = [];
    await page.route("**/api/**", async (route) => {
        const request = route.request();
        if (new URL(request.url()).pathname !== "/api/rules") {
            await route.fulfill({ status: 500, json: { error: "Unexpected API endpoint" } });
            return;
        }
        if (request.method() === "GET") {
            await route.fulfill({ json: document });
        } else if (request.method() === "PUT") {
            const saved: RulesDocument = request.postDataJSON();
            saves.push(saved);
            if (saveError) {
                await route.fulfill({ status: saveError.status, json: { error: saveError.error } });
            } else {
                document = { ...saved, revision: `${document.revision}\n# saved` };
                await route.fulfill({ json: document });
            }
        } else {
            await route.fulfill({ status: 405, json: { error: "Unexpected API method" } });
        }
    });
    return saves;
}

test("edits plain text, booleans, methods, and headers as typed JSON", async ({ page }) => {
    const saves = await mockApi(page, {
        revision: "original",
        rules: [{ index: 0, fields: { domain: "example.com", methods: ["GET", "HEAD"] } }],
    });
    await page.goto("/");
    await expect(page.getByRole("textbox", { name: "Rule 1 domain", exact: true })).toHaveValue(
        "example.com",
    );
    await expect(page.getByRole("button", { name: "Save changes" })).toBeDisabled();
    await page.getByRole("textbox", { name: "Rule 1 domain", exact: true }).fill("new.example.com");
    await page.getByRole("combobox", { name: "Rule 1 include_subdomains" }).selectOption("true");
    await page.getByRole("combobox", { name: "Rule 1 stream" }).selectOption("false");
    await page.getByRole("combobox", { name: "Rule 1 methods" }).selectOption("any");
    await page
        .getByRole("textbox", { name: "Rule 1 pathname_regex" })
        .fill(String.raw`^/api/\d+"quoted"$`);
    await page.getByRole("button", { name: "Add header" }).click();
    await page.getByRole("textbox", { name: "Rule 1 inject_headers 1 name" }).fill("X-Example");
    await page
        .getByRole("textbox", { name: "Rule 1 inject_headers 1 value" })
        .fill('a "quoted" value \\ suffix');
    await page.getByRole("button", { name: "Save changes" }).click();
    await expect(page.getByRole("status")).toHaveText("Changes saved.");
    expect(saves).toEqual([
        {
            revision: "original",
            rules: [
                {
                    index: 0,
                    fields: {
                        domain: "new.example.com",
                        include_subdomains: true,
                        stream: false,
                        methods: "ANY",
                        pathname_regex: String.raw`^/api/\d+"quoted"$`,
                        inject_headers: [
                            { name: "X-Example", value: 'a "quoted" value \\ suffix' },
                        ],
                    },
                },
            ],
        },
    ]);
    await expect(page.getByRole("textbox", { name: "Rule 1 pathname_regex" })).toHaveValue(
        String.raw`^/api/\d+"quoted"$`,
    );
    await expect(page.getByRole("button", { name: "Save changes" })).toBeDisabled();
});

test("keeps multiline lists and regex backslashes through a save", async ({ page }) => {
    const saves = await mockApi(page, {
        revision: "lists",
        rules: [
            {
                index: 0,
                fields: {
                    domain_regex: [String.raw`^one\.test$`, String.raw`^two\.test$`],
                    methods: ["POST"],
                },
            },
        ],
    });
    await page.goto("/");
    const regex = page.getByRole("textbox", { name: "Rule 1 domain_regex" });
    await expect(regex).toHaveValue(String.raw`^one\.test$` + "\n" + String.raw`^two\.test$`);
    await regex.fill(String.raw`^one\.test$` + "\n" + String.raw`^three\.test$`);
    await page.getByRole("combobox", { name: "Rule 1 methods" }).selectOption("any");
    await expect(page.getByRole("textbox", { name: "Rule 1 methods list" })).toHaveCount(0);
    await page.getByRole("combobox", { name: "Rule 1 methods" }).selectOption("custom");
    await expect(page.getByRole("textbox", { name: "Rule 1 methods list" })).toHaveValue(
        "GET\nHEAD",
    );
    await page.getByRole("textbox", { name: "Rule 1 methods list" }).fill("POST\nPATCH\nCUSTOM");
    await page.getByRole("button", { name: "Save changes" }).click();
    await expect(page.getByRole("status")).toHaveText("Changes saved.");
    expect(saves[0]?.rules[0]?.fields).toEqual({
        domain_regex: [String.raw`^one\.test$`, String.raw`^three\.test$`],
        methods: ["POST", "PATCH", "CUSTOM"],
    });
});

test("omits cleared optional fields and adds and removes rules", async ({ page }) => {
    const saves = await mockApi(page, {
        revision: "optional",
        rules: [
            {
                index: 0,
                fields: {
                    domain: "example.com",
                    include_subdomains: false,
                    methods: "ANY",
                    pathname_pattern: "/api/*",
                    inject_headers: [{ name: "X-Old", value: "old" }],
                },
            },
        ],
    });
    await page.goto("/");
    await page.getByRole("combobox", { name: "Rule 1 include_subdomains" }).selectOption("");
    await page.getByRole("combobox", { name: "Rule 1 methods" }).selectOption("default");
    await page.getByRole("textbox", { name: "Rule 1 pathname_pattern" }).fill("");
    await page.getByRole("button", { name: "Remove Rule 1 inject_headers 1" }).click();
    await page.getByRole("button", { name: "Add rule", exact: true }).click();
    await page
        .getByRole("textbox", { name: "Rule 2 domain", exact: true })
        .fill("other.test\nthird.test");
    await page.getByRole("button", { name: "Save changes" }).click();
    await expect(page.getByRole("status")).toHaveText("Changes saved.");
    expect(saves[0]?.rules).toEqual([
        { index: 0, fields: { domain: "example.com" } },
        { index: null, fields: { domain: ["other.test", "third.test"] } },
    ]);
    await page.getByRole("button", { name: "Remove rule", exact: true }).first().click();
    await expect(page.getByRole("textbox", { name: "Rule 1 domain", exact: true })).toHaveValue(
        "other.test\nthird.test",
    );
    await page.getByRole("button", { name: "Save changes" }).click();
    await expect(page.getByRole("status")).toHaveText("Changes saved.");
    expect(saves[1]?.rules).toEqual([
        { index: null, fields: { domain: ["other.test", "third.test"] } },
    ]);
});

for (const failure of [
    { status: 400, error: "Invalid domain regex" },
    { status: 409, error: "05-web.toml changed. Reload before saving." },
]) {
    test(`keeps unsaved input when the API returns ${failure.status}`, async ({ page }) => {
        await mockApi(
            page,
            { revision: "original", rules: [{ index: 0, fields: { domain: "example.com" } }] },
            failure,
        );
        await page.goto("/");
        await page
            .getByRole("textbox", { name: "Rule 1 domain", exact: true })
            .fill("changed.test");
        await page.getByRole("button", { name: "Save changes" }).click();
        await expect(page.getByRole("alert")).toHaveText(failure.error);
        await expect(page.getByRole("textbox", { name: "Rule 1 domain", exact: true })).toHaveValue(
            "changed.test",
        );
        await expect(page.getByRole("button", { name: "Save changes" })).toBeEnabled();
    });
}

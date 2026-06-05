const { Client } = require("@elastic/elasticsearch");
const client = new Client({
  node: process.env.ES_NODE || "http://localhost:9200",
  auth: {
    username: process.env.ES_USER || "elastic",
    password: process.env.ES_PASS || "changeme",
  },
  maxRetries: 3,
  requestTimeout: 10000,
});
const INDEX_NAME = "products";
const INDEX_MAPPING = {
  settings: {
    number_of_shards: 1,
    number_of_replicas: 1,
    analysis: {
      analyzer: {
        custom_text_analyzer: {
          type: "custom",
          tokenizer: "standard",
          filter: ["lowercase", "asciifolding"],
        },
      },
    },
  },
  mappings: {
    properties: {
      id: { type: "keyword" },
      name: {
        type: "text",
        analyzer: "custom_text_analyzer",
        fields: {
          keyword: { type: "keyword" },
        },
      },
      description: {
        type: "text",
        analyzer: "custom_text_analyzer",
      },
      category: { type: "keyword" },
      price: { type: "float" },
      in_stock: { type: "boolean" },
      tags: { type: "keyword" },
      created_at: { type: "date", format: "strict_date_optional_time" },
      location: { type: "geo_point" },
    },
  },
};
async function createIndex() {
  const exists = await client.indices.exists({ index: INDEX_NAME });
  if (exists) {
    console.log(`[INFO] Index "${INDEX_NAME}" already exists. Skipping.`);
    return;
  }
  await client.indices.create({
    index: INDEX_NAME,
    body: INDEX_MAPPING,
  });
  console.log(`[INFO] Index "${INDEX_NAME}" created successfully.`);
}
async function indexDocument(doc) {
  const response = await client.index({
    index: INDEX_NAME,
    id: doc.id,
    document: doc,
    refresh: "wait_for",
  });
  console.log(`[INFO] Indexed document: ${response._id} (${response.result})`);
  return response;
}
async function bulkIndex(docs) {
  const operations = docs.flatMap((doc) => [
    { index: { _index: INDEX_NAME, _id: doc.id } },
    doc,
  ]);
  const { errors, items } = await client.bulk({
    refresh: true,
    operations,
  });
  if (errors) {
    const failed = items.filter((item) => item.index?.error);
    console.error(`[ERROR] Bulk index had ${failed.length} failures:`, failed);
  } else {
    console.log(`[INFO] Bulk indexed ${docs.length} documents successfully.`);
  }
}
async function addMappingField(fieldName, fieldConfig) {
  await client.indices.putMapping({
    index: INDEX_NAME,
    body: {
      properties: {
        [fieldName]: fieldConfig,
      },
    },
  });
  console.log(`[INFO] Mapping updated: added field "${fieldName}".`);
}
async function reindexTo(targetIndex) {
  const response = await client.reindex({
    body: {
      source: { index: INDEX_NAME },
      dest: { index: targetIndex },
    },
    wait_for_completion: true,
  });
  console.log(`[INFO] Reindexed ${response.total} docs to "${targetIndex}".`);
  return response;
}
async function deleteIndex() {
  await client.indices.delete({ index: INDEX_NAME });
  console.log(`[INFO] Index "${INDEX_NAME}" deleted.`);
}
(async () => {
  try {
    await createIndex();
    await indexDocument({
      id: "prod-001",
      name: "Mechanical Keyboard",
      description: "Tactile switches, RGB backlit, TKL layout",
      category: "electronics",
      price: 129.99,
      in_stock: true,
      tags: ["keyboard", "peripheral", "rgb"],
      created_at: new Date().toISOString(),
      location: { lat: 37.7749, lon: -122.4194 },
    });
    await bulkIndex([
      {
        id: "prod-002",
        name: "USB-C Hub",
        description: "7-in-1 hub with HDMI, USB 3.0, and SD card",
        category: "electronics",
        price: 49.99,
        in_stock: true,
        tags: ["hub", "usb-c", "accessory"],
        created_at: new Date().toISOString(),
        location: { lat: 40.7128, lon: -74.006 },
      },
      {
        id: "prod-003",
        name: "Ergonomic Mouse",
        description: "Vertical grip, wireless, 1600 DPI",
        category: "electronics",
        price: 79.99,
        in_stock: false,
        tags: ["mouse", "ergonomic", "wireless"],
        created_at: new Date().toISOString(),
        location: { lat: 51.5074, lon: -0.1278 },
      },
    ]);
    await addMappingField("sku", { type: "keyword" });
    console.log("[DONE] All indexing operations completed.");
  } catch (err) {
    console.error("[FATAL]", err.message || err);
    process.exit(1);
  }
})();
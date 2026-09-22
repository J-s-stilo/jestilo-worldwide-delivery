const express = require("express");
const path = require("path");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();

app.use(express.json({ limit: "2mb" }));
app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});


/*
 * PRIVATE CUSTOMER SHIPMENT ROOM
 * package-room.html must sit beside server.js/index.html.
 */
app.get("/package-room.html", (req, res) => {
  res.sendFile(path.join(__dirname, "package-room.html"));
});



/* =========================================
   DATABASE
========================================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});


/* =========================================
   ENVIRONMENT
========================================= */

const PASSWORD = process.env.ADMIN_PASSWORD;
const RESEND_API_KEY = process.env.RESEND_API_KEY;

/*
  Optional but recommended:

  ADMIN_SESSION_SECRET

  If you don't create this variable, the
  ADMIN_PASSWORD is used as the signing secret.

  If ADMIN_SESSION_SECRET already exists,
  it is preferred.
*/

const SESSION_SECRET =
  process.env.ADMIN_SESSION_SECRET || PASSWORD;


if (!PASSWORD) {
  console.error("ADMIN_PASSWORD is not set.");
  process.exit(1);
}

if (!SESSION_SECRET) {
  console.error("ADMIN_SESSION_SECRET is not set.");
  process.exit(1);
}


/* =========================================
   DATABASE SETUP
========================================= */

async function setupDatabase() {

  await pool.query(`
    CREATE TABLE IF NOT EXISTS shipments (
      code TEXT PRIMARY KEY,
      customer TEXT DEFAULT '',
      email TEXT DEFAULT '',
      whatsapp TEXT DEFAULT '',
      item_name TEXT DEFAULT '',
      item_description TEXT DEFAULT '',
      image_url TEXT DEFAULT '',
      origin TEXT DEFAULT '',
      destination TEXT DEFAULT '',
      status TEXT DEFAULT 'Order received',
      location TEXT DEFAULT '',
      latitude DOUBLE PRECISION,
      longitude DOUBLE PRECISION,
      estimated_delivery TEXT DEFAULT '',
      note TEXT DEFAULT '',
      updated TEXT NOT NULL
    )
  `);


  const columns = [
    ["customer", "TEXT DEFAULT ''"],
    ["email", "TEXT DEFAULT ''"],
    ["whatsapp", "TEXT DEFAULT ''"],
    ["item_name", "TEXT DEFAULT ''"],
    ["item_description", "TEXT DEFAULT ''"],
    ["image_url", "TEXT DEFAULT ''"],
    ["origin", "TEXT DEFAULT ''"],
    ["destination", "TEXT DEFAULT ''"],
    ["status", "TEXT DEFAULT 'Order received'"],
    ["location", "TEXT DEFAULT ''"],
    ["latitude", "DOUBLE PRECISION"],
    ["longitude", "DOUBLE PRECISION"],
    ["estimated_delivery", "TEXT DEFAULT ''"],
    ["note", "TEXT DEFAULT ''"],
    ["updated", "TEXT"]
  ];


  for (const [name, definition] of columns) {

    await pool.query(`
      ALTER TABLE shipments
      ADD COLUMN IF NOT EXISTS ${name} ${definition}
    `);

  }



  /* =========================================
     PURCHASED ITEMS / PACKAGE MALL
     Linked directly to the shipment tracking code.
  ========================================= */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS package_mall_items (
      id BIGSERIAL PRIMARY KEY,
      tracking_code TEXT NOT NULL
        REFERENCES shipments(code)
        ON DELETE CASCADE,
      product_name TEXT DEFAULT '',
      image_url TEXT DEFAULT '',
      price NUMERIC(14,2) DEFAULT 0,
      currency TEXT DEFAULT 'USD',
      quantity INTEGER DEFAULT 1,
      seller TEXT DEFAULT '',
      purchase_status TEXT DEFAULT 'Purchased',
      purchase_date TEXT DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_package_mall_tracking_code
    ON package_mall_items(tracking_code)
  `);

  console.log("Database ready.");
}


/* =========================================
   HTML ESCAPE
========================================= */

function escapeHtml(value) {

  return String(value || "").replace(
    /[&<>"']/g,
    m => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;"
    }[m])
  );

}


/* =========================================
   ADMIN TOKEN
   Stateless signed token.
   Survives server restarts/redeploys.
========================================= */

function createAdminToken() {

  const payload = {
    type: "admin",
    exp: Date.now() + (7 * 24 * 60 * 60 * 1000)
  };


  const payloadString =
    JSON.stringify(payload);


  const encodedPayload =
    Buffer.from(payloadString)
      .toString("base64url");


  const signature =
    crypto
      .createHmac(
        "sha256",
        SESSION_SECRET
      )
      .update(encodedPayload)
      .digest("base64url");


  return `${encodedPayload}.${signature}`;
}


function verifyAdminToken(token) {

  if (!token || typeof token !== "string") {
    return false;
  }


  const parts =
    token.split(".");


  if (parts.length !== 2) {
    return false;
  }


  const [
    encodedPayload,
    providedSignature
  ] = parts;


  const expectedSignature =
    crypto
      .createHmac(
        "sha256",
        SESSION_SECRET
      )
      .update(encodedPayload)
      .digest("base64url");


  const providedBuffer =
    Buffer.from(
      providedSignature
    );


  const expectedBuffer =
    Buffer.from(
      expectedSignature
    );


  if (
    providedBuffer.length !==
    expectedBuffer.length
  ) {
    return false;
  }


  if (
    !crypto.timingSafeEqual(
      providedBuffer,
      expectedBuffer
    )
  ) {
    return false;
  }


  try {

    const payload =
      JSON.parse(
        Buffer.from(
          encodedPayload,
          "base64url"
        ).toString("utf8")
      );


    if (payload.type !== "admin") {
      return false;
    }


    if (
      !payload.exp ||
      Date.now() > payload.exp
    ) {
      return false;
    }


    return true;

  } catch (error) {

    return false;

  }

}


/* =========================================
   AUTHENTICATION
========================================= */

function auth(req, res, next) {

  const authorization =
    req.headers.authorization || "";


  if (
    !authorization.startsWith("Bearer ")
  ) {

    return res.status(401).json({
      error: "Unauthorized"
    });

  }


  const token =
    authorization.slice(7).trim();


  if (!verifyAdminToken(token)) {

    return res.status(401).json({
      error: "Unauthorized"
    });

  }


  next();
}


/* =========================================
   RESEND EMAIL
========================================= */

async function sendShipmentEmail(shipment) {

  if (
    !RESEND_API_KEY ||
    !shipment.email
  ) {
    return;
  }


  try {

    const response =
      await fetch(
        "https://api.resend.com/emails",
        {
          method: "POST",

          headers: {
            "Authorization":
              `Bearer ${RESEND_API_KEY}`,

            "Content-Type":
              "application/json"
          },

          body: JSON.stringify({

            from:
              "JESTILO Delivery Service <onboarding@resend.dev>",

            to: [
              shipment.email
            ],

            subject:
              `Shipment update - ${shipment.code}`,

            html: `

              <h2>
                JESTILO Delivery Service
              </h2>

              <p>
                Hello ${escapeHtml(
                  shipment.customer ||
                  "Customer"
                )},
              </p>

              <p>
                Your shipment information has been updated.
              </p>

              <p>
                <strong>Tracking:</strong>
                ${escapeHtml(shipment.code)}
              </p>

              ${
                shipment.item_name
                ? `
                  <p>
                    <strong>Item:</strong>
                    ${escapeHtml(
                      shipment.item_name
                    )}
                  </p>
                `
                : ""
              }

              <p>
                <strong>Status:</strong>
                ${escapeHtml(
                  shipment.status
                )}
              </p>

              ${
                shipment.origin
                ? `
                  <p>
                    <strong>Origin:</strong>
                    ${escapeHtml(
                      shipment.origin
                    )}
                  </p>
                `
                : ""
              }

              ${
                shipment.destination
                ? `
                  <p>
                    <strong>Destination:</strong>
                    ${escapeHtml(
                      shipment.destination
                    )}
                  </p>
                `
                : ""
              }

              ${
                shipment.location
                ? `
                  <p>
                    <strong>Current location:</strong>
                    ${escapeHtml(
                      shipment.location
                    )}
                  </p>
                `
                : ""
              }

              ${
                shipment.estimated_delivery
                ? `
                  <p>
                    <strong>Estimated delivery:</strong>
                    ${escapeHtml(
                      shipment.estimated_delivery
                    )}
                  </p>
                `
                : ""
              }

              ${
                shipment.note
                ? `
                  <p>
                    <strong>Update:</strong>
                    ${escapeHtml(
                      shipment.note
                    )}
                  </p>
                `
                : ""
              }

              <p>
                Please use your tracking number on the
                JESTILO Delivery Service website to view
                the latest available shipment information.
              </p>

            `
          })
        }
      );


    if (!response.ok) {

      const errorText =
        await response.text();

      console.error(
        "Resend email failed:",
        errorText
      );

      return;
    }


    console.log(
      "Shipment notification email sent."
    );


  } catch (error) {

    console.error(
      "Email notification error:",
      error
    );

  }

}


/* =========================================
   ADMIN LOGIN
========================================= */

app.post(
  "/api/admin/login",
  (req, res) => {

    const password =
      String(
        req.body?.password || ""
      );


    if (password !== PASSWORD) {

      return res.status(401).json({
        error: "Invalid password"
      });

    }


    const token =
      createAdminToken();


    res.json({
      token
    });

  }
);


/* =========================================
   CUSTOMER TRACKING
========================================= */

app.get(
  "/api/shipments/:code",
  async (req, res) => {

    try {

      const code =
        req.params.code
          .trim()
          .toUpperCase();


      const result =
        await pool.query(
          `
          SELECT *
          FROM shipments
          WHERE code = $1
          `,
          [code]
        );


      if (
        result.rows.length === 0
      ) {

        return res.sendStatus(404);

      }


      res.json(
        result.rows[0]
      );


    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Server error"
      });

    }

  }
);


/* =========================================
   CUSTOMER — PURCHASED ITEMS
========================================= */

app.get(
  "/api/shipments/:code/mall",
  async (req, res) => {
    try {
      const code =
        req.params.code
          .trim()
          .toUpperCase();

      const shipment =
        await pool.query(
          `
          SELECT code
          FROM shipments
          WHERE code = $1
          `,
          [code]
        );

      if (shipment.rows.length === 0) {
        return res.sendStatus(404);
      }

      const result =
        await pool.query(
          `
          SELECT
            id,
            tracking_code,
            product_name,
            image_url,
            price,
            currency,
            quantity,
            seller,
            purchase_status,
            purchase_date,
            created_at,
            updated_at
          FROM package_mall_items
          WHERE tracking_code = $1
          ORDER BY created_at ASC, id ASC
          `,
          [code]
        );

      res.json(result.rows);
    } catch (error) {
      console.error("Customer mall error:", error);
      res.status(500).json({
        error: "Server error"
      });
    }
  }
);


/* =========================================
   ADMIN — LIST PURCHASED ITEMS
========================================= */

app.get(
  "/api/admin/shipments/:code/mall",
  auth,
  async (req, res) => {
    try {
      const code =
        req.params.code
          .trim()
          .toUpperCase();

      const result =
        await pool.query(
          `
          SELECT *
          FROM package_mall_items
          WHERE tracking_code = $1
          ORDER BY created_at ASC, id ASC
          `,
          [code]
        );

      res.json(result.rows);
    } catch (error) {
      console.error("Admin mall list error:", error);
      res.status(500).json({
        error: "Server error"
      });
    }
  }
);


/* =========================================
   ADMIN — ADD PURCHASED ITEM
========================================= */

app.post(
  "/api/admin/shipments/:code/mall",
  auth,
  async (req, res) => {
    try {
      const code =
        req.params.code
          .trim()
          .toUpperCase();

      const shipment =
        await pool.query(
          `
          SELECT code
          FROM shipments
          WHERE code = $1
          `,
          [code]
        );

      if (shipment.rows.length === 0) {
        return res.status(404).json({
          error: "Shipment not found"
        });
      }

      const data = req.body || {};

      const productName =
        String(data.product_name || "").trim();

      const imageUrl =
        String(data.image_url || "").trim();

      const seller =
        String(data.seller || "").trim();

      const currency = "USD";

      const quantity =
        Math.max(
          1,
          parseInt(data.quantity, 10) || 1
        );

      const priceNumber =
        Number(data.price);

      const price =
        Number.isFinite(priceNumber) && priceNumber >= 0
          ? priceNumber
          : 0;

      const purchaseDate =
        String(data.purchase_date || "").trim();

      const purchaseStatus =
        String(
          data.purchase_status ||
          "Purchased"
        ).trim();

      if (!productName) {
        return res.status(400).json({
          error: "Product name required"
        });
      }

      const result =
        await pool.query(
          `
          INSERT INTO package_mall_items
          (
            tracking_code,
            product_name,
            image_url,
            price,
            currency,
            quantity,
            seller,
            purchase_status,
            purchase_date
          )
          VALUES
          (
            $1,$2,$3,$4,$5,$6,$7,$8,$9
          )
          RETURNING *
          `,
          [
            code,
            productName,
            imageUrl,
            price,
            currency,
            quantity,
            seller,
            purchaseStatus,
            purchaseDate
          ]
        );

      res.status(201).json(result.rows[0]);
    } catch (error) {
      console.error("Add mall item error:", error);
      res.status(500).json({
        error: "Could not save purchased item"
      });
    }
  }
);


/* =========================================
   ADMIN — EDIT PURCHASED ITEM
========================================= */

app.put(
  "/api/admin/mall/:id",
  auth,
  async (req, res) => {
    try {
      const id =
        Number.parseInt(req.params.id, 10);

      if (!Number.isInteger(id)) {
        return res.status(400).json({
          error: "Invalid item id"
        });
      }

      const data = req.body || {};

      const productName =
        String(data.product_name || "").trim();

      const imageUrl =
        String(data.image_url || "").trim();

      const seller =
        String(data.seller || "").trim();

      const quantity =
        Math.max(
          1,
          parseInt(data.quantity, 10) || 1
        );

      const priceNumber =
        Number(data.price);

      const price =
        Number.isFinite(priceNumber) && priceNumber >= 0
          ? priceNumber
          : 0;

      const purchaseDate =
        String(data.purchase_date || "").trim();

      const purchaseStatus =
        String(
          data.purchase_status ||
          "Purchased"
        ).trim();

      if (!productName) {
        return res.status(400).json({
          error: "Product name required"
        });
      }

      const result =
        await pool.query(
          `
          UPDATE package_mall_items
          SET
            product_name = $1,
            image_url = $2,
            price = $3,
            currency = 'USD',
            quantity = $4,
            seller = $5,
            purchase_status = $6,
            purchase_date = $7,
            updated_at = NOW()
          WHERE id = $8
          RETURNING *
          `,
          [
            productName,
            imageUrl,
            price,
            quantity,
            seller,
            purchaseStatus,
            purchaseDate,
            id
          ]
        );

      if (result.rows.length === 0) {
        return res.sendStatus(404);
      }

      res.json(result.rows[0]);
    } catch (error) {
      console.error("Edit mall item error:", error);
      res.status(500).json({
        error: "Could not update purchased item"
      });
    }
  }
);


/* =========================================
   ADMIN — DELETE PURCHASED ITEM
========================================= */

app.delete(
  "/api/admin/mall/:id",
  auth,
  async (req, res) => {
    try {
      const id =
        Number.parseInt(req.params.id, 10);

      if (!Number.isInteger(id)) {
        return res.status(400).json({
          error: "Invalid item id"
        });
      }

      const result =
        await pool.query(
          `
          DELETE FROM package_mall_items
          WHERE id = $1
          `,
          [id]
        );

      if (result.rowCount === 0) {
        return res.sendStatus(404);
      }

      res.sendStatus(204);
    } catch (error) {
      console.error("Delete mall item error:", error);
      res.status(500).json({
        error: "Could not delete purchased item"
      });
    }
  }
);


/* =========================================
   ADMIN — LIST SHIPMENTS
========================================= */

app.get(
  "/api/admin/shipments",
  auth,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT *
          FROM shipments
          ORDER BY updated DESC
          `
        );


      res.json(
        result.rows
      );


    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Server error"
      });

    }

  }
);


/* =========================================
   ADMIN — CREATE / UPDATE SHIPMENT
========================================= */

app.post(
  "/api/admin/shipments",
  auth,
  async (req, res) => {

    try {

      const data =
        req.body || {};


      const code =
        String(
          data.code || ""
        )
          .trim()
          .toUpperCase();


      if (!code) {

        return res.status(400).json({
          error:
            "Tracking number required"
        });

      }


      /* -------------------------
         LATITUDE
      ------------------------- */

      const latitude =
        data.latitude === "" ||
        data.latitude === null ||
        data.latitude === undefined
          ? null
          : Number(data.latitude);


      /* -------------------------
         LONGITUDE
      ------------------------- */

      const longitude =
        data.longitude === "" ||
        data.longitude === null ||
        data.longitude === undefined
          ? null
          : Number(data.longitude);


      /* -------------------------
         VALIDATE LATITUDE
      ------------------------- */

      if (
        latitude !== null &&
        (
          !Number.isFinite(latitude) ||
          latitude < -90 ||
          latitude > 90
        )
      ) {

        return res.status(400).json({
          error:
            "Invalid latitude"
        });

      }


      /* -------------------------
         VALIDATE LONGITUDE
      ------------------------- */

      if (
        longitude !== null &&
        (
          !Number.isFinite(longitude) ||
          longitude < -180 ||
          longitude > 180
        )
      ) {

        return res.status(400).json({
          error:
            "Invalid longitude"
        });

      }


      const shipment = {

        code,

        customer:
          String(
            data.customer || ""
          ).trim(),

        email:
          String(
            data.email || ""
          ).trim(),

        whatsapp:
          String(
            data.whatsapp || ""
          ).trim(),

        item_name:
          String(
            data.item_name || ""
          ).trim(),

        item_description:
          String(
            data.item_description || ""
          ).trim(),

        image_url:
          String(
            data.image_url || ""
          ).trim(),

        origin:
          String(
            data.origin || ""
          ).trim(),

        destination:
          String(
            data.destination || ""
          ).trim(),

        status:
          String(
            data.status ||
            "Order received"
          ).trim(),

        location:
          String(
            data.location || ""
          ).trim(),

        latitude,

        longitude,

        estimated_delivery:
          String(
            data.estimated_delivery || ""
          ).trim(),

        note:
          String(
            data.note || ""
          ).trim(),

        updated:
          new Date().toISOString()

      };


      await pool.query(

        `
        INSERT INTO shipments
        (
          code,
          customer,
          email,
          whatsapp,
          item_name,
          item_description,
          image_url,
          origin,
          destination,
          status,
          location,
          latitude,
          longitude,
          estimated_delivery,
          note,
          updated
        )

        VALUES
        (
          $1,$2,$3,$4,$5,$6,$7,
          $8,$9,$10,$11,$12,$13,$14,$15,$16
        )

        ON CONFLICT (code)

        DO UPDATE SET

          customer =
            EXCLUDED.customer,

          email =
            EXCLUDED.email,

          whatsapp =
            EXCLUDED.whatsapp,

          item_name =
            EXCLUDED.item_name,

          item_description =
            EXCLUDED.item_description,

          image_url =
            EXCLUDED.image_url,

          origin =
            EXCLUDED.origin,

          destination =
            EXCLUDED.destination,

          status =
            EXCLUDED.status,

          location =
            EXCLUDED.location,

          latitude =
            EXCLUDED.latitude,

          longitude =
            EXCLUDED.longitude,

          estimated_delivery =
            EXCLUDED.estimated_delivery,

          note =
            EXCLUDED.note,

          updated =
            EXCLUDED.updated
        `,

        [
          shipment.code,
          shipment.customer,
          shipment.email,
          shipment.whatsapp,
          shipment.item_name,
          shipment.item_description,
          shipment.image_url,
          shipment.origin,
          shipment.destination,
          shipment.status,
          shipment.location,
          shipment.latitude,
          shipment.longitude,
          shipment.estimated_delivery,
          shipment.note,
          shipment.updated
        ]

      );


      /*
        Send notification after successful
        database save.
      */

      await sendShipmentEmail(
        shipment
      );


      res.json(
        shipment
      );


    } catch (error) {

      console.error(
        "Save shipment error:",
        error
      );

      res.status(500).json({
        error:
          "Could not save shipment"
      });

    }

  }
);


/* =========================================
   ADMIN — DELETE SHIPMENT
========================================= */

app.delete(
  "/api/admin/shipments/:code",
  auth,
  async (req, res) => {

    try {

      const code =
        req.params.code
          .trim()
          .toUpperCase();


      await pool.query(
        `
        DELETE FROM shipments
        WHERE code = $1
        `,
        [code]
      );


      res.sendStatus(204);


    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not delete shipment"
      });

    }

  }
);


/* =========================================
   START SERVER
========================================= */

const port =
  process.env.PORT || 3000;


setupDatabase()

  .then(() => {

    app.listen(
      port,
      () => {

        console.log(
          `JESTILO Delivery Service running on port ${port}`
        );

      }
    );

  })

  .catch(error => {

    console.error(
      "Database setup failed:",
      error
    );

    process.exit(1);

  });

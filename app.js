const express = require('express');
const path = require('path');
const mysql = require('mysql2/promise');
const dotenv = require('dotenv');
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();
app.use(express.static(path.join(__dirname, '../public')));
app.get('/employees.html', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/employees.html'));
});
const PORT = Number(process.env.PORT || 3000);

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

/* =========================================================
   UPLOAD DIRECTORIES
========================================================= */

const uploads = path.join(__dirname, '..', 'uploads');
const profiles = path.join(uploads, 'profiles');
const resumes = path.join(uploads, 'resumes');

fs.mkdirSync(profiles, { recursive: true });
fs.mkdirSync(resumes, { recursive: true });

app.get('/add-employee.html', (req, res) => {
    res.sendFile(
        path.join(__dirname, '..', 'public', 'add-employee.html')
    );
});

/* =========================================================
   MYSQL CONNECTION
========================================================= */

const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'company',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    dateStrings: true
});

/* =========================================================
   PASSWORD HASH
========================================================= */

function passwordHash(password) {
    const salt = crypto.randomBytes(16).toString('hex');

    const hash = crypto
        .scryptSync(password, salt, 64)
        .toString('hex');

    return 'scrypt:' + salt + ':' + hash;
}
/* =========================================================
   PASSWORD VERIFICATION
========================================================= */

function verifyPassword(password, storedHash) {
    try {
        if (!password || !storedHash) {
            return false;
        }

        const parts = storedHash.split(':');

        if (parts.length !== 3 || parts[0] !== 'scrypt') {
            return false;
        }

        const salt = parts[1];
        const originalHash = Buffer.from(parts[2], 'hex');

        if (originalHash.length !== 64) {
            return false;
        }

        const inputHash = crypto.scryptSync(
            password,
            salt,
            64
        );

        return crypto.timingSafeEqual(
            inputHash,
            originalHash
        );

    } catch (error) {
        return false;
    }
}
/* =========================================================
   AUTHENTICATION MIDDLEWARE
========================================================= */

function authenticateToken(req, res, next) {

    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {

        return res.status(401).json({
            success: false,
            message: 'Authentication required.'
        });

    }

    const token = authHeader.substring(7);

    if (!process.env.JWT_SECRET) {

        return res.status(500).json({
            success: false,
            message: 'JWT_SECRET is not configured.'
        });

    }

    try {

        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        req.user = decoded;

        next();

    } catch (error) {

        return res.status(401).json({
            success: false,
            message: 'Invalid or expired session.'
        });

    }

}
/* =========================================================
   PERMISSION CHECK
========================================================= */

async function hasPermission(employeeId, menu, action) {

    const [rows] = await pool.query(
        `
        SELECT 1
        FROM company.employees e

        INNER JOIN security.role_permissions rp
            ON rp.role_id = e.role_id

        INNER JOIN security.permissions p
            ON p.permission_id = rp.permission_id

        WHERE e.employee_id = ?
          AND p.menu = ?
          AND p.action = ?

        LIMIT 1
        `,
        [
            employeeId,
            menu,
            action
        ]
    );

    return rows.length > 0;
}
/* =========================================================
   REQUIRE PERMISSION
========================================================= */

function requirePermission(menu, action) {
    return async function (req, res, next) {

        try {

            // First verify JWT
            authenticateToken(req, res, async function () {

                try {

                    const employeeId =
                        Number(req.user.employee_id);

                    if (!employeeId) {
                        return res.status(401).json({
                            success: false,
                            message: 'Invalid employee session.'
                        });
                    }

                    const allowed =
                        await hasPermission(
                            employeeId,
                            menu,
                            action
                        );

                    if (!allowed) {

                        return res.status(403).json({
                            success: false,
                            message:
                                `Permission denied: ${menu} ${action}`
                        });

                    }

                    next();

                } catch (error) {

                    console.error(
                        'PERMISSION CHECK ERROR:',
                        error
                    );

                    return res.status(500).json({
                        success: false,
                        message:
                            'Permission check failed.'
                    });

                }

            });

        } catch (error) {

            console.error(
                'RBAC ERROR:',
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    'Authorization failed.'
            });

        }

    };
}
/* =========================================================
   EMPLOYEE DATA SCOPE
========================================================= */

async function isSelfScopedEmployee(employeeId) {

    const [rows] = await pool.query(
        `
        SELECT
            r.role_name
        FROM company.employees e
        INNER JOIN security.roles r
            ON r.role_id = e.role_id
        WHERE e.employee_id = ?
          AND e.account_status = 'ACTIVE'
        LIMIT 1
        `,
        [employeeId]
    );

    if (!rows.length) {
        return false;
    }

    return String(rows[0].role_name).toLowerCase() === 'employee';
}
/* =========================================================
   EMPLOYEE SELF DATA SCOPE
========================================================= */

async function requireEmployeeSelfScope(req, res, next) {
    try {
        const loggedInEmployeeId =
            Number(req.user.employee_id);

        const requestedEmployeeId =
            Number(req.params.id);

        if (!loggedInEmployeeId || !requestedEmployeeId) {
            return res.status(400).json({
                success: false,
                message: 'Invalid employee ID.'
            });
        }

        const selfScoped =
            await isSelfScopedEmployee(
                loggedInEmployeeId
            );

        /*
         * Normal Employee:
         * Can only open their own employee record.
         *
         * HR / Manager / Director / CFO / CEO:
         * Data scope is not restricted here.
         */
        if (
            selfScoped &&
            requestedEmployeeId !== loggedInEmployeeId
        ) {
            return res.status(403).json({
                success: false,
                message:
                    'Access denied: You can only view your own employee details.'
            });
        }

        next();

    } catch (error) {

        console.error(
            'EMPLOYEE SCOPE ERROR:',
            error
        );

        return res.status(500).json({
            success: false,
            message:
                'Employee access scope check failed.'
        });
    }
}
/* =========================================================
   AUDIT LOG
========================================================= */

async function audit(req, data) {
    try {
        await pool.query(
            `
            INSERT INTO security.audit_logs
            (
                employee_id,
                action,
                schema_name,
                table_name,
                record_id,
                old_data,
                new_data,
                ip_address,
                user_agent
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            `,
            [
                data.employee_id || 2,
                data.action,
                data.schema || 'company',
                data.table || 'employees',
                data.record_id || null,
                data.old_data
                    ? JSON.stringify(data.old_data)
                    : null,
                data.new_data
                    ? JSON.stringify(data.new_data)
                    : null,
                req.ip,
                req.get('user-agent') || null
            ]
        );
    } catch (e) {
        console.warn(
            'Audit log warning:',
            e.message
        );
    }
}

/* =========================================================
   PROFILE UPLOAD
========================================================= */

const profileStorage = multer.diskStorage({

    destination: function (req, file, cb) {
        cb(null, profiles);
    },

    filename: function (req, file, cb) {

        cb(
            null,
            String(req.params.employeeId) +
            path.extname(file.originalname).toLowerCase()
        );

    }

});

const uploadProfile = multer({

    storage: profileStorage,

    limits: {
        fileSize: 5 * 1024 * 1024
    },

    fileFilter: function (req, file, cb) {

        cb(
            null,
            /\.(jpg|jpeg|png|webp)$/i.test(
                path.extname(file.originalname)
            )
        );

    }

});

/* =========================================================
   RESUME UPLOAD
========================================================= */

const resumeStorage = multer.diskStorage({

    destination: function (req, file, cb) {
        cb(null, resumes);
    },

    filename: function (req, file, cb) {

        cb(
            null,
            String(req.params.employeeId) +
            path.extname(file.originalname).toLowerCase()
        );

    }

});

const uploadResume = multer({

    storage: resumeStorage,

    limits: {
        fileSize: 10 * 1024 * 1024
    },

    fileFilter: function (req, file, cb) {

        cb(
            null,
            /\.(pdf|doc|docx)$/i.test(
                path.extname(file.originalname)
            )
        );

    }

});

/* =========================================================
   FILE HELPER
========================================================= */

function fileFor(dir, employeeId) {

    try {

        const found =
            fs.readdirSync(dir).find(
                function (name) {

                    return (
                        path.parse(name).name ===
                        String(employeeId)
                    );

                }
            );

        return found || null;

    } catch (e) {

        return null;

    }

}

/* =========================================================
   EMPLOYEE QUERY
========================================================= */

const employeeSelect = `
SELECT
    e.employee_id,
    e.username,
    e.email,
    e.first_name,
    e.last_name,
    e.phone,
    e.date_of_birth,
    e.department_id,
    e.role_id,
    e.job_title,
    e.manager_id,
    e.joining_date,
    e.account_status,

    d.department_name,

    r.role_name,

    CONCAT(
        COALESCE(m.first_name, ''),
        ' ',
        COALESCE(m.last_name, '')
    ) AS manager_name

FROM company.employees e

JOIN company.departments d
    ON d.department_id =
       e.department_id

JOIN security.roles r
    ON r.role_id =
       e.role_id

LEFT JOIN company.employees m
    ON m.employee_id =
       e.manager_id
`;

/* =========================================================
   ADD FILE URLS
========================================================= */

function withFiles(row) {

    const profile =
        fileFor(
            profiles,
            row.employee_id
        );

    const resume =
        fileFor(
            resumes,
            row.employee_id
        );

    row.profile_url =
        profile
            ? '/uploads/profiles/' + profile
            : null;

    row.resume_url =
        resume
            ? '/uploads/resumes/' + resume
            : null;

    return row;

}

/* =========================================================
   HEALTH
========================================================= */

app.get(
    '/api/health',
    async function (req, res) {

        try {

            const connection =
                await pool.getConnection();

            await connection.ping();

            connection.release();

            res.json({
                status: 'OK',
                database: 'MySQL connected'
            });

        } catch (e) {

            res.status(500).json({
                status: 'ERROR',
                error: e.message
            });

        }

    }
);

/* =========================================================
   DEPARTMENTS
========================================================= */

app.get(
    '/api/departments',
    requirePermission('Department', 'VIEW'),
    async function (req, res) {

        try {

            const [rows] =
                await pool.query(
                    `
                    SELECT
                        department_id,
                        department_name,
                        description
                    FROM company.departments
                    ORDER BY department_name
                    `
                );

            res.json(rows);

        } catch (e) {

            res.status(500).json({
                message: e.message
            });

        }

    }
);

app.post(
    '/api/departments',
    requirePermission('Department', 'ADD'),
    async function (req, res) {

        try {

            const name =
                String(
                    req.body.department_name || ''
                ).trim();

            const description =
                String(
                    req.body.description || ''
                ).trim() || null;

            if (!name) {

                return res.status(400).json({
                    message:
                        'Department name is required.'
                });

            }

            const [result] =
                await pool.query(
                    `
                    INSERT INTO company.departments
                    (
                        department_name,
                        description
                    )
                    VALUES (?, ?)
                    `,
                    [
                        name,
                        description
                    ]
                );

            await audit(
                req,
                {
                    action:
                        'DEPARTMENT_CREATED',

                    table:
                        'departments',

                    record_id:
                        result.insertId,

                    new_data: {
                        department_id:
                            result.insertId,

                        department_name:
                            name,

                        description:
                            description
                    }
                }
            );

            res.status(201).json({
                success: true,
                department_id:
                    result.insertId
            });

        } catch (e) {

            res.status(400).json({
                message:
                    e.code ===
                    'ER_DUP_ENTRY'
                        ? 'Department already exists.'
                        : e.message
            });

        }

    }
);

/* =========================================================
   ROLES
========================================================= */

app.get(
    '/api/roles',
    async function (req, res) {

        try {

            const [rows] =
                await pool.query(
                    `
                    SELECT
                        role_id,
                        role_name,
                        description
                    FROM security.roles
                    ORDER BY role_id
                    `
                );

            res.json(rows);

        } catch (e) {

            res.status(500).json({
                message: e.message
            });

        }

    }
);

/* =========================================================
   GET EMPLOYEES
========================================================= */

app.get(
    '/api/employees',
    requirePermission('Employee', 'VIEW'),
    async function (req, res) {

        try {

            const employeeId =
                Number(req.user.employee_id);

            const selfScoped =
                await isSelfScopedEmployee(employeeId);

            let query =
                employeeSelect;

            let params = [];

            /*
             * Normal Employee:
             * Can only see their own employee record.
             *
             * HR / CEO / other permitted roles:
             * Can see the full employee list.
             */

            if (selfScoped) {

                query += `
                    WHERE
                        e.employee_id = ?
                `;

                params = [
                    employeeId
                ];

            }

            query += `
                ORDER BY
                    e.employee_id
            `;

            const [rows] =
                await pool.query(
                    query,
                    params
                );

            res.json(
                rows.map(withFiles)
            );

        } catch (e) {

            console.error(
                'GET EMPLOYEES ERROR:',
                e
            );

            res.status(500).json({
                success: false,
                message:
                    'Failed to load employees.'
            });

        }

    }
);

/* =========================================================
   GET SINGLE EMPLOYEE
========================================================= */

app.get(
    '/api/employees/:id',
    requirePermission('Employee', 'VIEW'),
    requireEmployeeSelfScope,
    async function (req, res) {

        try {

            const [rows] =
                await pool.query(
                    employeeSelect +
                    `
                    WHERE
                        e.employee_id = ?
                    `,
                    [
                        Number(
                            req.params.id
                        )
                    ]
                );

            if (!rows.length) {

                return res.status(404).json({
                    message:
                        'Employee not found.'
                });

            }

            res.json(
                withFiles(rows[0])
            );

        } catch (e) {

            res.status(500).json({
                message: e.message
            });

        }

    }
);

/* =========================================================
   ADD EMPLOYEE
========================================================= */

app.post(
    '/api/employees',
    requirePermission('Employee', 'ADD'),
    async function (req, res) {

        const b = req.body;

        try {

            const required = [
                'username',
                'email',
                'password',
                'first_name',
                'last_name',
                'department_id',
                'role_id',
                'job_title',
                'joining_date'
            ];

            const missing =
                required.filter(
                    function (field) {

                        return !b[field];

                    }
                );

            if (missing.length) {

                return res.status(400).json({
                    message:
                        'Required fields: ' +
                        missing.join(', ')
                });

            }

            const [result] =
                await pool.query(
                    `
                    INSERT INTO company.employees
                    (
                        username,
                        email,
                        password_hash,
                        first_name,
                        last_name,
                        phone,
                        date_of_birth,
                        department_id,
                        role_id,
                        job_title,
                        manager_id,
                        joining_date,
                        account_status
                    )
                    VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    `,
                    [

                        b.username.trim(),

                        b.email.trim(),

                        passwordHash(
                            b.password
                        ),

                        b.first_name.trim(),

                        b.last_name.trim(),

                        b.phone ||
                            null,

                        b.date_of_birth ||
                            null,

                        Number(
                            b.department_id
                        ),

                        Number(
                            b.role_id
                        ),

                        b.job_title.trim(),

                        b.manager_id
                            ? Number(
                                b.manager_id
                            )
                            : null,

                        b.joining_date,

                        b.account_status ||
                            'ACTIVE'

                    ]
                );

            await audit(
                req,
                {

                    action:
                        'EMPLOYEE_CREATED',

                    record_id:
                        result.insertId,

                    new_data: {

                        employee_id:
                            result.insertId,

                        username:
                            b.username,

                        email:
                            b.email,

                        first_name:
                            b.first_name,

                        last_name:
                            b.last_name,

                        department_id:
                            Number(
                                b.department_id
                            ),

                        role_id:
                            Number(
                                b.role_id
                            ),

                        job_title:
                            b.job_title,

                        manager_id:
                            b.manager_id
                                ? Number(
                                    b.manager_id
                                )
                                : null,

                        joining_date:
                            b.joining_date,

                        account_status:
                            b.account_status ||
                            'ACTIVE'

                    }

                }
            );

            res.status(201).json({

                success:
                    true,

                employee_id:
                    result.insertId

            });

        } catch (e) {

            res.status(400).json({

                message:
                    e.code ===
                    'ER_DUP_ENTRY'
                        ? 'Username or email already exists.'
                        : e.message

            });

        }

    }
);

/* =========================================================
   UPDATE EMPLOYEE
========================================================= */

app.put(
    '/api/employees/:id',
    requirePermission('Employee', 'EDIT'),
    async function (req, res) {

        const id =
            Number(
                req.params.id
            );

        const b =
            req.body;

        try {

            const [oldRows] =
                await pool.query(
                    `
                    SELECT *
                    FROM company.employees
                    WHERE employee_id = ?
                    `,
                    [id]
                );

            if (!oldRows.length) {

                return res.status(404).json({
                    message:
                        'Employee not found.'
                });

            }

            const connection =
                await pool.getConnection();

            try {

                await connection.query(
                    `
                    CALL company.sp_update_employee(
                        ?,
                        ?,
                        ?,
                        ?,
                        ?,
                        ?,
                        ?,
                        ?,
                        ?,
                        ?,
                        ?,
                        ?,
                        ?
                    )
                    `,
                    [

                        Number(
                            b.actor_employee_id
                        ) || 2,

                        id,

                        b.first_name,

                        b.last_name,

                        b.email,

                        b.phone ||
                            null,

                        b.date_of_birth ||
                            null,

                        Number(
                            b.department_id
                        ),

                        Number(
                            b.role_id
                        ),

                        b.job_title,

                        b.manager_id
                            ? Number(
                                b.manager_id
                            )
                            : null,

                        b.joining_date,

                        b.account_status

                    ]
                );

            } finally {

                connection.release();

            }

            await audit(
                req,
                {

                    action:
                        'EMPLOYEE_UPDATED',

                    record_id:
                        id,

                    old_data:
                        oldRows[0],

                    new_data:
                        b

                }
            );

            res.json({
                success:
                    true
            });

        } catch (e) {

            res.status(400).json({
                message:
                    e.message
            });

        }

    }
);

/* =========================================================
   DEACTIVATE EMPLOYEE
========================================================= */

app.delete(
    '/api/employees/:id',
    requirePermission('Employee', 'DELETE'),
    async function (req, res) {

        const id =
            Number(
                req.params.id
            );

        try {

            const [rows] =
                await pool.query(
                    `
                    SELECT *
                    FROM company.employees
                    WHERE employee_id = ?
                    `,
                    [id]
                );

            if (!rows.length) {

                return res.status(404).json({
                    message:
                        'Employee not found.'
                });

            }

            await pool.query(
                `
                UPDATE company.employees
                SET account_status = 'INACTIVE'
                WHERE employee_id = ?
                `,
                [id]
            );

            await audit(
                req,
                {

                    action:
                        'EMPLOYEE_DEACTIVATED',

                    record_id:
                        id,

                    old_data:
                        rows[0],

                    new_data: {
                        account_status:
                            'INACTIVE'
                    }

                }
            );

            res.json({
                success:
                    true
            });

        } catch (e) {

            res.status(400).json({
                message:
                    e.message
            });

        }

    }
);

/* =========================================================
   PROFILE UPLOAD
========================================================= */

app.post(
    '/api/employees/:employeeId/profile',
    uploadProfile.single('profile'),
    async function (req, res) {

        try {

            if (!req.file) {

                return res.status(400).json({
                    message:
                        'Choose a JPG, JPEG, PNG or WEBP image.'
                });

            }

            const id =
                Number(
                    req.params.employeeId
                );

            const [rows] =
                await pool.query(
                    `
                    SELECT employee_id
                    FROM company.employees
                    WHERE employee_id = ?
                    `,
                    [id]
                );

            if (!rows.length) {

                fs.unlinkSync(
                    req.file.path
                );

                return res.status(404).json({
                    message:
                        'Employee not found.'
                });

            }

            fs.readdirSync(
                profiles
            ).forEach(
                function (name) {

                    if (
                        path.parse(name)
                            .name ===
                            String(id) &&
                        name !==
                            req.file.filename
                    ) {

                        try {

                            fs.unlinkSync(
                                path.join(
                                    profiles,
                                    name
                                )
                            );

                        } catch {}

                    }

                }
            );

            res.json({

                success:
                    true,

                url:
                    '/uploads/profiles/' +
                    req.file.filename

            });

        } catch (e) {

            res.status(400).json({
                message:
                    e.message
            });

        }

    }
);

/* =========================================================
   RESUME UPLOAD
========================================================= */

app.post(
    '/api/employees/:employeeId/resume',
    uploadResume.single('resume'),
    async function (req, res) {

        try {

            if (!req.file) {

                return res.status(400).json({
                    message:
                        'Choose a PDF, DOC or DOCX resume.'
                });

            }

            const id =
                Number(
                    req.params.employeeId
                );

            const [rows] =
                await pool.query(
                    `
                    SELECT employee_id
                    FROM company.employees
                    WHERE employee_id = ?
                    `,
                    [id]
                );

            if (!rows.length) {

                fs.unlinkSync(
                    req.file.path
                );

                return res.status(404).json({
                    message:
                        'Employee not found.'
                });

            }

            fs.readdirSync(
                resumes
            ).forEach(
                function (name) {

                    if (
                        path.parse(name)
                            .name ===
                            String(id) &&
                        name !==
                            req.file.filename
                    ) {

                        try {

                            fs.unlinkSync(
                                path.join(
                                    resumes,
                                    name
                                )
                            );

                        } catch {}

                    }

                }
            );

            res.json({

                success:
                    true,

                url:
                    '/uploads/resumes/' +
                    req.file.filename

            });

        } catch (e) {

            res.status(400).json({
                message:
                    e.message
            });

        }

    }
);

/* =========================================================
   SALARIES
========================================================= */

app.get(
    '/api/salaries',
    async function (req, res) {

        try {

            const [rows] =
                await pool.query(
                    `
                    SELECT
                        s.salary_id,
                        s.employee_id,

                        CONCAT(
                            e.first_name,
                            ' ',
                            e.last_name
                        ) AS employee,

                        s.basic_salary,
                        s.allowances,
                        s.deductions,
                        s.currency,
                        s.effective_from,

                        s.basic_salary +
                        s.allowances
                            AS gross_salary,

                        s.basic_salary +
                        s.allowances -
                        s.deductions
                            AS net_salary

                    FROM payroll.salaries s

                    JOIN company.employees e
                        ON e.employee_id =
                           s.employee_id

                    ORDER BY
                        e.employee_id
                    `
                );

            res.json(rows);

        } catch (e) {

            res.status(500).json({
                message:
                    e.message
            });

        }

    }
);

/* =========================================================
   ROLE PERMISSIONS
========================================================= */

app.get(
    '/api/role-permissions',
    async function (req, res) {

        try {

            const [rows] =
                await pool.query(
                    `
                    SELECT
                        r.role_name,
                        p.menu,
                        p.action,
                        p.description

                    FROM security.role_permissions rp

                    JOIN security.roles r
                        ON r.role_id =
                           rp.role_id

                    JOIN security.permissions p
                        ON p.permission_id =
                           rp.permission_id

                    ORDER BY
                        r.role_id,
                        p.menu,
                        p.permission_id
                    `
                );

            res.json(rows);

        } catch (e) {

            res.status(500).json({
                message:
                    e.message
            });

        }

    }
);

/* =========================================================
   AUDIT LOGS
========================================================= */

app.get(
    '/api/audit-logs',
    async function (req, res) {

        try {

            const [rows] =
                await pool.query(
                    `
                    SELECT
                        a.audit_id,
                        a.employee_id,

                        CONCAT(
                            COALESCE(
                                e.first_name,
                                ''
                            ),
                            ' ',
                            COALESCE(
                                e.last_name,
                                ''
                            )
                        ) AS actor,

                        a.action,
                        a.schema_name,
                        a.table_name,
                        a.record_id,
                        a.created_at

                    FROM security.audit_logs a

                    LEFT JOIN company.employees e
                        ON e.employee_id =
                           a.employee_id

                    ORDER BY
                        a.audit_id DESC

                    LIMIT 200
                    `
                );

            res.json(rows);

        } catch (e) {

            res.status(500).json({
                message:
                    e.message
            });

        }

    }
);

/* =========================================================
   PROFESSIONAL ADMIN WEBSITE
========================================================= */

app.get(
    '/',
    function (req, res) {

        const html = String.raw`
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>Company Management</title>

<style>

:root {

    --blue: #1a73e8;
    --blue-dark: #1557b0;

    --text: #202124;
    --muted: #6b7280;

    --line: #e5e7eb;

    --background: #f8fafd;

    --card: #ffffff;

    --green: #188038;
    --red: #d93025;

}

* {
    box-sizing: border-box;
}

body {

    margin: 0;

    font-family:
        Arial,
        Helvetica,
        sans-serif;

    background:
        var(--background);

    color:
        var(--text);

    font-size: 14px;

}

/* =========================================================
   APP
========================================================= */

.app {

    display: flex;

    min-height: 100vh;

}

/* =========================================================
   SIDEBAR
========================================================= */

.sidebar {

    width: 252px;

    background: #ffffff;

    border-right:
        1px solid
        var(--line);

    position: fixed;

    top: 0;
    bottom: 0;
    left: 0;

    z-index: 20;

    display: flex;

    flex-direction: column;

}

.logo {

    height: 72px;

    padding:
        0 22px;

    display: flex;

    align-items: center;

    gap: 11px;

    font-size: 19px;

    font-weight: 700;

    border-bottom:
        1px solid
        var(--line);

}

.logoMark {

    width: 30px;
    height: 30px;

    border-radius: 8px;

    background:
        var(--blue);

    color: #fff;

    display: grid;

    place-items: center;

    font-weight: 800;

}

.sectionLabel {

    padding:
        24px 18px 8px;

    color:
        #8a9099;

    font-size: 10px;

    font-weight: 800;

    letter-spacing:
        .12em;

    text-transform:
        uppercase;

}

.nav {

    padding:
        0 10px;

}

.nav button {

    width: 100%;

    border: 0;

    background:
        transparent;

    text-align: left;

    padding:
        11px 12px;

    margin:
        2px 0;

    border-radius: 8px;

    color:
        #4b5563;

    font-size: 14px;

    cursor: pointer;

    display: flex;

    align-items: center;

    gap: 11px;

}

.nav button:hover {

    background:
        #f5f7fa;

}

.nav button.active {

    background:
        #e8f0fe;

    color:
        #185abc;

    font-weight: 700;

}

.navIcon {

    width: 20px;

    text-align:
        center;

    font-size: 16px;

}

.sideBottom {

    margin-top: auto;

    padding: 14px;

    border-top:
        1px solid
        var(--line);

    color:
        #6b7280;

    font-size: 12px;

}

/* =========================================================
   MAIN
========================================================= */

.main {

    margin-left: 252px;

    width:
        calc(
            100% - 252px
        );

}

.topbar {

    height: 72px;

    background: #ffffff;

    border-bottom:
        1px solid
        var(--line);

    display: flex;

    align-items: center;

    padding:
        0 28px;

    gap: 18px;

    position: sticky;

    top: 0;

    z-index: 10;

}

.globalSearch {

    width:
        min(
            620px,
            55vw
        );

    height: 42px;

    background:
        #f1f3f4;

    border:
        1px solid
        transparent;

    border-radius: 8px;

    display: flex;

    align-items: center;

    padding:
        0 13px;

    gap: 9px;

}

.globalSearch:focus-within {

    background:
        #ffffff;

    border-color:
        #9aa0a6;

    box-shadow:
        0 1px 3px
        #0001;

}

.globalSearch input {

    border: 0;

    outline: 0;

    background:
        transparent;

    width: 100%;

    font-size: 14px;

}

.topSpacer {

    flex: 1;

}

.statusDot {

    width: 8px;
    height: 8px;

    background:
        #1e8e3e;

    border-radius:
        50%;

    display:
        inline-block;

}

.account {

    display: flex;

    align-items:
        center;

    gap: 10px;

}

.avatar {

    width: 36px;
    height: 36px;

    border-radius:
        50%;

    background:
        #e8f0fe;

    color:
        #185abc;

    display:
        grid;

    place-items:
        center;

    font-weight:
        700;

}

.accountText {

    line-height:
        1.2;

}

.accountText small {

    color:
        var(--muted);

}

/* =========================================================
   CONTENT
========================================================= */

.content {

    padding: 28px;

    max-width:
        1600px;

    margin:
        auto;

}

.page {

    display:
        none;

}

.page.active {

    display:
        block;

}

.pageHead {

    display:
        flex;

    justify-content:
        space-between;

    align-items:
        flex-start;

    gap: 20px;

    margin-bottom:
        22px;

}

.eyebrow {

    color:
        var(--blue);

    font-size:
        12px;

    font-weight:
        700;

    text-transform:
        uppercase;

    letter-spacing:
        .08em;

    margin-bottom:
        6px;

}

.pageHead h1 {

    font-size:
        28px;

    line-height:
        1.2;

    margin:
        0 0 6px;

}

.pageHead p {

    margin:
        0;

    color:
        var(--muted);

}

.actions {

    display:
        flex;

    gap:
        9px;

    align-items:
        center;

}

/* =========================================================
   BUTTONS
========================================================= */

.btn {

    height:
        38px;

    padding:
        0 14px;

    border:
        1px solid
        #dadce0;

    border-radius:
        7px;

    background:
        #ffffff;

    color:
        #303134;

    font-weight:
        600;

    cursor:
        pointer;

}

.btn:hover {

    background:
        #f8f9fa;

}

.btn.primary {

    background:
        var(--blue);

    border-color:
        var(--blue);

    color:
        #ffffff;

}

.btn.primary:hover {

    background:
        var(--blue-dark);

}

.btn.danger {

    color:
        var(--red);

}

.btn.small {

    height:
        32px;

    padding:
        0 10px;

    font-size:
        12px;

}

/* =========================================================
   STAT CARDS
========================================================= */

.cards {

    display:
        grid;

    grid-template-columns:
        repeat(
            4,
            1fr
        );

    gap:
        16px;

    margin-bottom:
        20px;

}

.card {

    background:
        var(--card);

    border:
        1px solid
        var(--line);

    border-radius:
        10px;

    padding:
        20px;

    box-shadow:
        0 1px 2px
        #00000008;

}

.cardTop {

    display:
        flex;

    justify-content:
        space-between;

    align-items:
        center;

}

.cardLabel {

    font-size:
        11px;

    color:
        #6b7280;

    font-weight:
        800;

    letter-spacing:
        .08em;

}

.cardIcon {

    width:
        34px;

    height:
        34px;

    border-radius:
        8px;

    background:
        #f1f5ff;

    display:
        grid;

    place-items:
        center;

    color:
        var(--blue);

}

.cardNum {

    font-size:
        29px;

    font-weight:
        700;

    margin-top:
        14px;

}

.cardSub {

    font-size:
        12px;

    color:
        #6b7280;

    margin-top:
        5px;

}

/* =========================================================
   PANELS
========================================================= */

.grid2 {

    display:
        grid;

    grid-template-columns:
        1.4fr 1fr;

    gap:
        20px;

}

.panel {

    background:
        #ffffff;

    border:
        1px solid
        var(--line);

    border-radius:
        10px;

    overflow:
        hidden;

    box-shadow:
        0 1px 2px
        #00000008;

}

.panelHead {

    height:
        60px;

    padding:
        0 20px;

    border-bottom:
        1px solid
        var(--line);

    display:
        flex;

    align-items:
        center;

    justify-content:
        space-between;

}

.panelHead h2 {

    font-size:
        16px;

    margin:
        0;

}

.quick {

    display:
        grid;

    grid-template-columns:
        1fr 1fr;

    gap:
        10px;

    padding:
        16px;

}

.quick button {

    padding:
        16px;

    text-align:
        left;

    border:
        1px solid
        var(--line);

    border-radius:
        8px;

    background:
        #ffffff;

    cursor:
        pointer;

}

.quick button:hover {

    border-color:
        #b8c2d1;

    background:
        #fafcff;

}

.quick b {

    display:
        block;

    margin-bottom:
        5px;

}

.quick span {

    font-size:
        12px;

    color:
        var(--muted);

}

/* =========================================================
   TOOLBAR
========================================================= */

.toolbar {

    display:
        flex;

    gap:
        9px;

    flex-wrap:
        wrap;

    padding:
        14px;

    border-bottom:
        1px solid
        var(--line);

}

.input,
.select {

    height:
        40px;

    border:
        1px solid
        #d6d9de;

    border-radius:
        7px;

    background:
        #ffffff;

    padding:
        0 11px;

    outline:
        0;

}

.input:focus,
.select:focus {

    border-color:
        #8ab4f8;

    box-shadow:
        0 0 0 2px
        #8ab4f833;

}

.grow {

    flex:
        1;

    min-width:
        240px;

}

/* =========================================================
   TABLE
========================================================= */

.tableWrap {

    overflow:
        auto;

}

table {

    width:
        100%;

    border-collapse:
        collapse;

    min-width:
        900px;

}

th {

    background:
        #f8f9fa;

    color:
        #6b7280;

    font-size:
        10px;

    text-transform:
        uppercase;

    letter-spacing:
        .07em;

    text-align:
        left;

    padding:
        12px 16px;

    border-bottom:
        1px solid
        var(--line);

    white-space:
        nowrap;

}

td {

    padding:
        13px 16px;

    border-bottom:
        1px solid
        #f0f1f3;

    vertical-align:
        middle;

}

tr:hover td {

    background:
        #fbfcfe;

}

.person {

    display:
        flex;

    align-items:
        center;

    gap:
        10px;

}

.personAvatar {

    width:
        34px;

    height:
        34px;

    border-radius:
        50%;

    background:
        #eef2f7;

    display:
        grid;

    place-items:
        center;

    font-weight:
        700;

    color:
        #475569;

    flex:
        none;

}

.personName {

    font-weight:
        700;

}

.muted {

    font-size:
        12px;

    color:
        var(--muted);

    margin-top:
        3px;

}

.badge {

    display:
        inline-flex;

    align-items:
        center;

    padding:
        5px 8px;

    border-radius:
        12px;

    background:
        #f1f3f4;

    color:
        #5f6368;

    font-size:
        10px;

    font-weight:
        800;

}

.badge.active {

    background:
        #e6f4ea;

    color:
        var(--green);

}

.badge.inactive {

    background:
        #fce8e6;

    color:
        var(--red);

}

.rowActions {

    display:
        flex;

    gap:
        6px;

}

.empty {

    text-align:
        center;

    padding:
        45px;

    color:
        #6b7280;

}

/* =========================================================
   RECENT LIST
========================================================= */

.listRow {

    display:
        flex;

    align-items:
        center;

    justify-content:
        space-between;

    padding:
        15px 20px;

    border-bottom:
        1px solid
        #f0f1f3;

}

.listRow:last-child {

    border-bottom:
        0;

}

/* =========================================================
   MODAL
========================================================= */

.modal {

    position:
        fixed;

    inset:
        0;

    background:
        #0008;

    display:
        none;

    align-items:
        center;

    justify-content:
        center;

    padding:
        20px;

    z-index:
        50;

}

.modal.show {

    display:
        flex;

}

.modalBox {

    width:
        min(
            900px,
            96vw
        );

    max-height:
        92vh;

    overflow:
        auto;

    background:
        #ffffff;

    border-radius:
        12px;

    box-shadow:
        0 20px 60px
        #0005;

}

.modalHead {

    height:
        64px;

    padding:
        0 22px;

    border-bottom:
        1px solid
        var(--line);

    display:
        flex;

    align-items:
        center;

    justify-content:
        space-between;

}

.modalHead h2 {

    font-size:
        18px;

    margin:
        0;

}

.close {

    border:
        0;

    background:
        #f1f3f4;

    width:
        34px;

    height:
        34px;

    border-radius:
        50%;

    cursor:
        pointer;

    font-size:
        18px;

}

.modalBody {

    padding:
        22px;

}

.formGrid {

    display:
        grid;

    grid-template-columns:
        1fr 1fr;

    gap:
        17px;

}

.field {

    display:
        flex;

    flex-direction:
        column;

    gap:
        6px;

}

.field label {

    font-size:
        12px;

    font-weight:
        700;

    color:
        #4b5563;

}

.field input,
.field select {

    height:
        40px;

    border:
        1px solid
        #d6d9de;

    border-radius:
        7px;

    padding:
        0 10px;

    outline:
        0;

    background:
        #ffffff;

}

.field input:focus,
.field select:focus {

    border-color:
        #8ab4f8;

    box-shadow:
        0 0 0 2px
        #8ab4f833;

}

.help {

    font-size:
        11px;

    color:
        #6b7280;

}

.modalFoot {

    padding:
        14px 22px;

    border-top:
        1px solid
        var(--line);

    display:
        flex;

    justify-content:
        flex-end;

    gap:
        9px;

}

/* =========================================================
   DRAWER
========================================================= */

.drawer {

    position:
        fixed;

    right:
        0;

    top:
        0;

    bottom:
        0;

    width:
        min(
            470px,
            94vw
        );

    background:
        #ffffff;

    box-shadow:
        -10px 0 35px
        #0002;

    z-index:
        45;

    transform:
        translateX(105%);

    transition:
        transform .2s ease;

    padding:
        25px;

    overflow:
        auto;

}

.drawer.show {

    transform:
        translateX(0);

}

.drawerTop {

    display:
        flex;

    justify-content:
        space-between;

    align-items:
        flex-start;

}

.profileLarge {

    width:
        70px;

    height:
        70px;

    border-radius:
        50%;

    background:
        #e8f0fe;

    color:
        #185abc;

    display:
        grid;

    place-items:
        center;

    font-size:
        23px;

    font-weight:
        700;

    margin-bottom:
        15px;

}

.detail {

    display:
        flex;

    justify-content:
        space-between;

    gap:
        20px;

    padding:
        13px 0;

    border-bottom:
        1px solid
        #eee;

}

.detail span {

    color:
        #6b7280;

}

.detail b {

    text-align:
        right;

}

.fileBox {

    margin-top:
        20px;

    padding:
        14px;

    border:
        1px solid
        var(--line);

    border-radius:
        8px;

}

/* =========================================================
   QUICK LIST
========================================================= */

.quick button {

    font-family:
        inherit;

}

/* =========================================================
   TOAST
========================================================= */

.toast {

    position:
        fixed;

    right:
        22px;

    bottom:
        22px;

    background:
        #202124;

    color:
        #ffffff;

    padding:
        12px 16px;

    border-radius:
        8px;

    box-shadow:
        0 8px 30px
        #0003;

    display:
        none;

    z-index:
        100;

}

.toast.show {

    display:
        block;

}

/* =========================================================
   RESPONSIVE
========================================================= */

@media(max-width:1100px) {

    .cards {

        grid-template-columns:
            1fr 1fr;

    }

    .grid2 {

        grid-template-columns:
            1fr;

    }

}

@media(max-width:760px) {

    .sidebar {

        width:
            68px;

    }

    .logo {

        padding:
            0;

        justify-content:
            center;

    }

    .logoText,
    .sectionLabel,
    .nav button span:not(.navIcon),
    .sideBottom {

        display:
            none;

    }

    .nav button {

        justify-content:
            center;

    }

    .main {

        margin-left:
            68px;

        width:
            calc(
                100% - 68px
            );

    }

    .content {

        padding:
            18px;

    }

    .topbar {

        padding:
            0 15px;

    }

    .accountText {

        display:
            none;

    }

    .globalSearch {

        width:
            55vw;

    }

    .formGrid {

        grid-template-columns:
            1fr;

    }

    .pageHead {

        flex-direction:
            column;

    }

}

@media(max-width:500px) {

    .cards {

        grid-template-columns:
            1fr;

    }

    .globalSearch {

        width:
            48vw;

    }

    .actions {

        width:
            100%;

    }

    .actions .btn {

        flex:
            1;

    }

}

</style>

</head>

<body>

<div class="app">

<!-- =====================================================
     SIDEBAR
====================================================== -->

<aside class="sidebar">

    <div class="logo">

        <div class="logoMark">
            C
        </div>

        <span class="logoText">
            Company Management
        </span>

    </div>

    <div class="sectionLabel">
        Workspace
    </div>

    <nav class="nav">

        <button
            class="active"
            onclick="showPage('overview',this)"
        >

            <span class="navIcon">
                ⌂
            </span>

            <span>
                Overview
            </span>

        </button>

        <button
            onclick="showPage('employees',this)"
        >

            <span class="navIcon">
                ♙
            </span>

            <span>
                Employees
            </span>

        </button>

        <button
    id="departmentsNav"
    onclick="showPage('departments',this)"
>

            <span class="navIcon">
                ▤
            </span>

            <span>
                Departments
            </span>

        </button>

        <button
    id="rolesNav"
    onclick="showPage('roles',this)"
>

            <span class="navIcon">
                ◆
            </span>

            <span>
                Roles & Permissions
            </span>

        </button>

       <button
    id="payrollNav"
    onclick="showPage('payroll',this)"
>

            <span class="navIcon">
                ₹
            </span>

            <span>
                Payroll
            </span>

        </button>
        <button
    id="timesheetsNav"
    onclick="window.location.href='/timesheets.html'"
>
    <span class="navIcon">◷</span>
    <span>Timesheets</span>
</button>

<button
    id="projectsNav"
    style="display: none;"
    onclick="window.location.href='/projects.html'"
>
    <span class="navIcon">◈</span>
    <span>Projects</span>
</button>

    </nav>

    <div class="sectionLabel">
        Security
    </div>

    <nav class="nav">

        <button
    id="auditNav"
    onclick="showPage('audit',this)"
>

            <span class="navIcon">
                ◷
            </span>

            <span>
                Audit Logs
            </span>

        </button>

    </nav>

    <div class="sideBottom">

        <span class="statusDot"></span>

        API connected

        <br>
        <br>

        Development workspace

    </div>

</aside>


<!-- =====================================================
     MAIN
====================================================== -->

<main class="main">

<header class="topbar">

    <div class="globalSearch">

        <span>
            ⌕
        </span>

        <input
            id="globalSearch"
            placeholder="Search employees, email or job title"
            oninput="globalSearch(this.value)"
        >

    </div>

    <div class="topSpacer"></div>

    <span class="statusDot"></span>

    <span
        style="
        font-size:12px;
        color:#6b7280
        "
    >
        API ONLINE
    </span>

    <div class="account">

        <div class="avatar">
            PS
        </div>

        <div class="accountText">

            <b>
                Priya Sharma
            </b>

            <br>

            <small>
                HR Administrator
            </small>

        </div>

    </div>

</header>

<section class="content">

<!-- =====================================================
     OVERVIEW
====================================================== -->

<section
    id="overview"
    class="page active"
>

    <div class="pageHead">

        <div>

            <div class="eyebrow">
                Company workspace
            </div>

            <h1>
                Overview
            </h1>

            <p>
                Manage people, organization, access and payroll from one place.
            </p>

        </div>

        <div class="actions">

            <button
                class="btn"
                onclick="refreshAll()"
            >
                Refresh
            </button>

            <button
                class="btn primary"
                onclick="window.location.href='/add-employee.html'"
            >
                + Add employee
            </button>

        </div>

    </div>

    <div class="cards">

        <div class="card">

            <div class="cardTop">

                <span class="cardLabel">
                    EMPLOYEES
                </span>

                <div class="cardIcon">
                    ♙
                </div>

            </div>

            <div
                class="cardNum"
                id="statEmployees"
            >
                —
            </div>

            <div class="cardSub">
                All employee records
            </div>

        </div>

        <div class="card">

            <div class="cardTop">

                <span class="cardLabel">
                    ACTIVE
                </span>

                <div class="cardIcon">
                    ✓
                </div>

            </div>

            <div
                class="cardNum"
                id="statActive"
            >
                —
            </div>

            <div class="cardSub">
                Active accounts
            </div>

        </div>

        <div class="card">

            <div class="cardTop">

                <span class="cardLabel">
                    DEPARTMENTS
                </span>

                <div class="cardIcon">
                    ▤
                </div>

            </div>

            <div
                class="cardNum"
                id="statDepartments"
            >
                —
            </div>

            <div class="cardSub">
                Organizational units
            </div>

        </div>

        <div class="card">

            <div class="cardTop">

                <span class="cardLabel">
                    ROLES
                </span>

                <div class="cardIcon">
                    ◆
                </div>

            </div>

            <div
                class="cardNum"
                id="statRoles"
            >
                —
            </div>

            <div class="cardSub">
                Security roles
            </div>

        </div>

    </div>

    <div class="grid2">

        <div class="panel">

            <div class="panelHead">

                <h2>
                    Recently added employees
                </h2>

                <button
                    class="btn small"
                    onclick="goEmployees()"
                >
                    View all
                </button>

            </div>

            <div
                id="recentEmployees"
            ></div>

        </div>

       <div class="panel" id="quickActionsPanel">

    <div class="panelHead">

        <h2>
            Quick actions
        </h2>

            </div>

            <div class="quick">

                <button
                    onclick="openEmployeeModal()"
                >

                    <b>
                        Add employee
                    </b>

                    <span>
                        Create a new employee account
                    </span>

                </button>

                <button
                    onclick="openDepartmentModal()"
                >

                    <b>
                        Add department
                    </b>

                    <span>
                        Create an organizational unit
                    </span>

                </button>

                <button
                    onclick="goEmployees()"
                >

                    <b>
                        Manage employees
                    </b>

                    <span>
                        Search, edit or deactivate
                    </span>

                </button>

                <button
                    onclick="goAudit()"
                >

                    <b>
                        View audit logs
                    </b>

                    <span>
                        Review application activity
                    </span>

                </button>

            </div>

        </div>

    </div>

</section>

<!-- =====================================================
     EMPLOYEES
====================================================== -->

<section
    id="employees"
    class="page"
>

    <div class="pageHead">

        <div>

            <div class="eyebrow">
                People
            </div>

            <h1>
                Employees
            </h1>

            <p>
                Search and manage employee records, reporting lines and account status.
            </p>

        </div>

        <button
    class="btn primary"
    onclick="window.location.href='/add-employee'"
>
    + Add employee
</button>

    </div>

    <div class="panel">

        <div class="toolbar">

            <input
                class="input grow"
                id="employeeSearch"
                placeholder="Search name, username or email"
                oninput="renderEmployees()"
            >

            <select
                class="select"
                id="departmentFilter"
                onchange="renderEmployees()"
            >

                <option value="">
                    All departments
                </option>

            </select>

            <select
                class="select"
                id="statusFilter"
                onchange="renderEmployees()"
            >

                <option value="">
                    All status
                </option>

                <option value="ACTIVE">
                    Active
                </option>

                <option value="INACTIVE">
                    Inactive
                </option>

                <option value="LOCKED">
                    Locked
                </option>

                <option value="SUSPENDED">
                    Suspended
                </option>

            </select>

            <button
                class="btn"
                onclick="loadEmployees()"
            >
                Refresh
            </button>

        </div>

        <div class="tableWrap">

            <table>

                <thead>

                    <tr>

                        <th>
                            Employee
                        </th>

                        <th>
                            Email
                        </th>

                        <th>
                            Department
                        </th>

                        <th>
                            Role
                        </th>

                        <th>
                            Manager
                        </th>

                        <th>
                            Status
                        </th>

                        <th>
                            Actions
                        </th>

                    </tr>

                </thead>

                <tbody
                    id="employeeTable"
                ></tbody>

            </table>

        </div>

    </div>

</section>

<!-- =====================================================
     DEPARTMENTS
====================================================== -->

<section
    id="departments"
    class="page"
>

    <div class="pageHead">

        <div>

            <div class="eyebrow">
                Organization
            </div>

            <h1>
                Departments
            </h1>

            <p>
                Manage organizational units and view employee counts.
            </p>

        </div>

        <button
            class="btn primary"
            onclick="openDepartmentModal()"
        >
            + Add department
        </button>

    </div>

    <div class="panel">

        <div class="tableWrap">

            <table>

                <thead>

                    <tr>

                        <th>
                            ID
                        </th>

                        <th>
                            Department
                        </th>

                        <th>
                            Description
                        </th>

                        <th>
                            Employees
                        </th>

                    </tr>

                </thead>

                <tbody
                    id="departmentTable"
                ></tbody>

            </table>

        </div>

    </div>

</section>

<!-- =====================================================
     ROLES
====================================================== -->

<section
    id="roles"
    class="page"
>

    <div class="pageHead">

        <div>

            <div class="eyebrow">
                Security
            </div>

            <h1>
                Roles & Permissions
            </h1>

            <p>
                Review the role-to-menu/action assignments stored in MySQL.
            </p>

        </div>

    </div>

    <div class="panel">

        <div class="tableWrap">

            <table>

                <thead>

                    <tr>

                        <th>
                            Role
                        </th>

                        <th>
                            Menu
                        </th>

                        <th>
                            Action
                        </th>

                        <th>
                            Description
                        </th>

                    </tr>

                </thead>

                <tbody
                    id="roleTable"
                ></tbody>

            </table>

        </div>

    </div>

</section>

<!-- =====================================================
     PAYROLL
====================================================== -->

<section
    id="payroll"
    class="page"
>

    <div class="pageHead">

        <div>

            <div class="eyebrow">
                Compensation
            </div>

            <h1>
                Payroll
            </h1>

            <p>
                Salary records with calculated gross and net values.
            </p>

        </div>

    </div>

    <div class="panel">

        <div class="tableWrap">

            <table>

                <thead>

                    <tr>

                        <th>
                            Employee
                        </th>

                        <th>
                            Basic
                        </th>

                        <th>
                            Allowances
                        </th>

                        <th>
                            Deductions
                        </th>

                        <th>
                            Gross
                        </th>

                        <th>
                            Net
                        </th>

                        <th>
                            Currency
                        </th>

                        <th>
                            Effective
                        </th>

                    </tr>

                </thead>

                <tbody
                    id="salaryTable"
                ></tbody>

            </table>

        </div>

    </div>

</section>

<!-- =====================================================
     AUDIT
====================================================== -->

<section
    id="audit"
    class="page"
>

    <div class="pageHead">

        <div>

            <div class="eyebrow">
                Security
            </div>

            <h1>
                Audit Logs
            </h1>

            <p>
                Recent changes made through the application.
            </p>

        </div>

        <button
            class="btn"
            onclick="loadAudit()"
        >
            Refresh
        </button>

    </div>

    <div class="panel">

        <div class="tableWrap">

            <table>

                <thead>

                    <tr>

                        <th>
                            ID
                        </th>

                        <th>
                            Actor
                        </th>

                        <th>
                            Action
                        </th>

                        <th>
                            Table
                        </th>

                        <th>
                            Record
                        </th>

                        <th>
                            Timestamp
                        </th>

                    </tr>

                </thead>

                <tbody
                    id="auditTable"
                ></tbody>

            </table>

        </div>

    </div>

</section>

</section>

</main>

</div>

<!-- =====================================================
     EMPLOYEE MODAL
====================================================== -->

<div
    class="modal"
    id="employeeModal"
>

<div class="modalBox">

    <div class="modalHead">

        <h2 id="employeeModalTitle">
            Add employee
        </h2>

        <button
            class="close"
            onclick="closeEmployeeModal()"
        >
            ×
        </button>

    </div>

    <form
        id="employeeForm"
    >

        <div class="modalBody">

            <div class="formGrid">

                <div class="field">

                    <label>
                        Username *
                    </label>

                    <input
                        id="f_username"
                        required
                    >

                </div>

                <div
                    class="field"
                    id="passwordField"
                >

                    <label>
                        Password *
                    </label>

                    <input
                        id="f_password"
                        type="password"
                    >

                    <span class="help">
                        Stored as a scrypt password hash.
                    </span>

                </div>

                <div class="field">

                    <label>
                        First name *
                    </label>

                    <input
                        id="f_first"
                        required
                    >

                </div>

                <div class="field">

                    <label>
                        Last name *
                    </label>

                    <input
                        id="f_last"
                        required
                    >

                </div>

                <div class="field">

                    <label>
                        Email *
                    </label>

                    <input
                        id="f_email"
                        type="email"
                        required
                    >

                </div>

                <div class="field">

                    <label>
                        Phone
                    </label>

                    <input
                        id="f_phone"
                    >

                </div>

                <div class="field">

                    <label>
                        Date of birth
                    </label>

                    <input
                        id="f_dob"
                        type="date"
                    >

                </div>

                <div class="field">

                    <label>
                        Joining date *
                    </label>

                    <input
                        id="f_join"
                        type="date"
                        required
                    >

                </div>

                <div class="field">

                    <label>
                        Department *
                    </label>

                    <select
                        id="f_dept"
                        required
                    ></select>

                </div>

                <div class="field">

                    <label>
                        Role *
                    </label>

                    <select
                        id="f_role"
                        required
                    ></select>

                </div>

                <div class="field">

                    <label>
                        Job title *
                    </label>

                    <input
                        id="f_job"
                        required
                    >

                </div>

                <div class="field">

                    <label>
                        Manager
                    </label>

                    <select
                        id="f_manager"
                    ></select>

                </div>

                <div class="field">

                    <label>
                        Account status
                    </label>

                    <select
                        id="f_status"
                    >

                        <option>
                            ACTIVE
                        </option>

                        <option>
                            INACTIVE
                        </option>

                        <option>
                            LOCKED
                        </option>

                        <option>
                            SUSPENDED
                        </option>

                    </select>

                </div>

                <div class="field">

                    <label>
                        Profile picture
                    </label>

                    <input
                        id="f_profile"
                        type="file"
                        accept="image/png,image/jpeg,image/webp"
                    >

                    <span class="help">
                        JPG, PNG or WEBP. Max 5 MB.
                    </span>

                </div>

                <div class="field">

                    <label>
                        Resume
                    </label>

                    <input
                        id="f_resume"
                        type="file"
                        accept="application/pdf,.doc,.docx"
                    >

                    <span class="help">
                        PDF, DOC or DOCX. Max 10 MB.
                    </span>

                </div>

            </div>

        </div>

        <div class="modalFoot">

            <button
                type="button"
                class="btn"
                onclick="closeEmployeeModal()"
            >
                Cancel
            </button>

            <button
                class="btn primary"
                id="saveEmployee"
            >
                Create employee
            </button>

        </div>

    </form>

</div>

</div>

<!-- =====================================================
     DEPARTMENT MODAL
====================================================== -->

<div
    class="modal"
    id="departmentModal"
>

<div
    class="modalBox"
    style="max-width:650px"
>

    <div class="modalHead">

        <h2>
            Add department
        </h2>

        <button
            class="close"
            onclick="closeDepartmentModal()"
        >
            ×
        </button>

    </div>

    <form
        id="departmentForm"
    >

        <div class="modalBody">

            <div class="formGrid">

                <div class="field">

                    <label>
                        Department name *
                    </label>

                    <input
                        id="d_name"
                        required
                    >

                </div>

                <div class="field">

                    <label>
                        Description
                    </label>

                    <input
                        id="d_desc"
                    >

                </div>

            </div>

        </div>

        <div class="modalFoot">

            <button
                type="button"
                class="btn"
                onclick="closeDepartmentModal()"
            >
                Cancel
            </button>

            <button
                class="btn primary"
            >
                Create department
            </button>

        </div>

    </form>

</div>

</div>

<!-- =====================================================
     EMPLOYEE DRAWER
====================================================== -->

<div
    class="drawer"
    id="employeeDrawer"
>

    <div class="drawerTop">

        <div>

            <div
                class="profileLarge"
                id="drawerAvatar"
            >
                --
            </div>

            <h2
                id="drawerName"
                style="margin:0 0 5px"
            ></h2>

            <div
                id="drawerTitle"
                class="muted"
            ></div>

        </div>

        <button
            class="close"
            onclick="closeDrawer()"
        >
            ×
        </button>

    </div>

    <div
        id="drawerBody"
        style="margin-top:20px"
    ></div>

    <div
        id="drawerFiles"
    ></div>

    <div
        style="margin-top:20px"
    >

        <button
            class="btn primary"
            id="drawerEdit"
        >
            Edit employee
        </button>

    </div>

</div>

<div
    class="toast"
    id="toast"
></div>

<script>

var employees = [];

var departments = [];

var roles = [];

var editId = null;


/* =====================================================
   HELPERS
===================================================== */

function $(id) {

    return document.getElementById(id);

}


function esc(value) {

    return String(
        value == null
            ? ''
            : value
    ).replace(
        /[&<>"']/g,
        function (c) {

            return {

                '&':
                    '&amp;',

                '<':
                    '&lt;',

                '>':
                    '&gt;',

                '"':
                    '&quot;',

                "'":
                    '&#39;'

            }[c];

        }
    );

}


function dateOnly(value) {

    return value
        ? String(value).slice(0, 10)
        : '';

}


function money(value) {

    return Number(
        value || 0
    ).toLocaleString(
        'en-IN',
        {
            minimumFractionDigits: 2,
            maximumFractionDigits: 2
        }
    );

}


function toast(message) {

    $('toast').textContent =
        message;

    $('toast')
        .classList
        .add('show');

    setTimeout(
        function () {

            $('toast')
                .classList
                .remove('show');

        },
        2800
    );

}


async function api(
    url,
    options
) {

    options = options || {};

    options.headers = {
        ...(options.headers || {})
    };

    const token =
        localStorage.getItem('authToken');

    if (token) {

        options.headers.Authorization =
            'Bearer ' + token;

    }

    var response =
        await fetch(
            url,
            options
        );

    var data =
        await response
            .json()
            .catch(
                function () {
                    return {};
                }
            );

    if (!response.ok) {

        throw new Error(
            data.message ||
            data.error ||
            'Request failed'
        );

    }

    return data;

}


/* =====================================================
   NAVIGATION
===================================================== */

function showPage(
    id,
    button
) {

    document
        .querySelectorAll(
            '.page'
        )
        .forEach(
            function (element) {

                element
                    .classList
                    .remove(
                        'active'
                    );

            }
        );

    $(id)
        .classList
        .add('active');

    document
        .querySelectorAll(
            '.nav button'
        )
        .forEach(
            function (element) {

                element
                    .classList
                    .remove(
                        'active'
                    );

            }
        );

    if (button) {

        button
            .classList
            .add('active');

    }

    if (
        id ===
        'departments'
    ) {

        loadDepartments();

    }

    if (
        id ===
        'roles'
    ) {

        loadRoles();

    }

    if (
        id ===
        'payroll'
    ) {

        loadSalary();

    }

    if (
        id ===
        'audit'
    ) {

        loadAudit();

    }

}


function goEmployees() {

    var button =
        document
            .querySelectorAll(
                '.nav button'
            )[1];

    showPage(
        'employees',
        button
    );

}


function goAudit() {

    var button =
        document
            .querySelectorAll(
                '.nav button'
            )[5];

    showPage(
        'audit',
        button
    );

}


function globalSearch(value) {

    if (
        $('employees')
            .classList
            .contains('active')
    ) {

        $('employeeSearch')
            .value =
            value;

        renderEmployees();

    }

}


/* =====================================================
   EMPLOYEE DATA
===================================================== */

async function loadEmployees() {

    try {

        employees =
            await api(
                '/api/employees'
            );

        departments =
            await api(
                '/api/departments'
            );

        roles =
            await api(
                '/api/roles'
            );

        populateSelects();

        renderEmployees();

        renderRecent();

        updateStats();

    } catch (error) {

        toast(
            error.message
        );

    }

}


function updateStats() {

    $('statEmployees')
        .textContent =
        employees.length;

    $('statActive')
        .textContent =
        employees.filter(
            function (employee) {

                return (
                    employee.account_status ===
                    'ACTIVE'
                );

            }
        ).length;

    $('statDepartments')
        .textContent =
        departments.length;

    $('statRoles')
        .textContent =
        roles.length;

}


function populateSelects() {

    $('departmentFilter')
        .innerHTML =
        '<option value="">All departments</option>' +
        departments
            .map(
                function (department) {

                    return (
                        '<option value="' +
                        department.department_id +
                        '">' +
                        esc(
                            department.department_name
                        ) +
                        '</option>'
                    );

                }
            )
            .join('');

    $('f_dept')
        .innerHTML =
        departments
            .map(
                function (department) {

                    return (
                        '<option value="' +
                        department.department_id +
                        '">' +
                        esc(
                            department.department_name
                        ) +
                        '</option>'
                    );

                }
            )
            .join('');

    $('f_role')
        .innerHTML =
        roles
            .map(
                function (role) {

                    return (
                        '<option value="' +
                        role.role_id +
                        '">' +
                        esc(
                            role.role_name
                        ) +
                        '</option>'
                    );

                }
            )
            .join('');

    $('f_manager')
        .innerHTML =
        '<option value="">No manager</option>' +
        employees
            .filter(
                function (employee) {

                    return (
                        employee.employee_id !==
                        editId
                    );

                }
            )
            .map(
                function (employee) {

                    return (
                        '<option value="' +
                        employee.employee_id +
                        '">' +
                        esc(
                            employee.first_name +
                            ' ' +
                            employee.last_name +
                            ' · ' +
                            employee.job_title
                        ) +
                        '</option>'
                    );

                }
            )
            .join('');

}


function renderRecent() {

    var rows =
        employees
            .slice()
            .reverse()
            .slice(
                0,
                6
            );

    if (!rows.length) {

        $('recentEmployees')
            .innerHTML =
            '<div class="empty">No employees found.</div>';

        return;

    }

    $('recentEmployees')
        .innerHTML =
        rows
            .map(
                function (employee) {

                    var initials =
                        (
                            employee.first_name ||
                            '?'
                        )[0] +
                        (
                            employee.last_name ||
                            '?'
                        )[0];

                    return (

                        '<div class="listRow">' +

                            '<div class="person">' +

                                '<div class="personAvatar">' +
                                    esc(
                                        initials
                                    ) +
                                '</div>' +

                                '<div>' +

                                    '<div class="personName">' +
                                        esc(
                                            employee.first_name +
                                            ' ' +
                                            employee.last_name
                                        ) +
                                    '</div>' +

                                    '<div class="muted">' +
                                        esc(
                                            employee.job_title
                                        ) +
                                        ' · ' +
                                        esc(
                                            employee.department_name
                                        ) +
                                    '</div>' +

                                '</div>' +

                            '</div>' +

                            '<button class="btn small" onclick="viewEmployee(' +
                                employee.employee_id +
                            ')">' +
                                'View' +
                            '</button>' +

                        '</div>'

                    );

                }
            )
            .join('');

}


function renderEmployees() {

    var search =
        (
            $('employeeSearch')
                .value ||
            ''
        )
        .toLowerCase()
        .trim();

    var department =
        $('departmentFilter')
            .value;

    var status =
        $('statusFilter')
            .value;

    var rows =
        employees.filter(
            function (employee) {

                var text =
                    (
                        employee.first_name +
                        ' ' +
                        employee.last_name +
                        ' ' +
                        employee.email +
                        ' ' +
                        employee.username +
                        ' ' +
                        employee.job_title
                    )
                    .toLowerCase();

                return (

                    (
                        !search ||
                        text.indexOf(
                            search
                        ) >= 0
                    )

                    &&

                    (
                        !department ||
                        String(
                            employee.department_id
                        ) ===
                        department
                    )

                    &&

                    (
                        !status ||
                        employee.account_status ===
                        status
                    )

                );

            }
        );

    if (!rows.length) {

        $('employeeTable')
            .innerHTML =
            '<tr><td colspan="7" class="empty">No employees match your filters.</td></tr>';

        return;

    }

    $('employeeTable')
        .innerHTML =
        rows
            .map(
                function (employee) {

                    var initials =
                        (
                            employee.first_name ||
                            '?'
                        )[0] +
                        (
                            employee.last_name ||
                            '?'
                        )[0];

                    initials =
                        initials.toUpperCase();

                    var badge =
                        employee.account_status ===
                        'ACTIVE'
                            ? 'active'
                            : 'inactive';

                    return (

                        '<tr>' +

                            '<td>' +

                                '<div class="person">' +

                                    '<div class="personAvatar">' +
                                        esc(
                                            initials
                                        ) +
                                    '</div>' +

                                    '<div>' +

                                        '<div class="personName">' +
                                            esc(
                                                employee.first_name +
                                                ' ' +
                                                employee.last_name
                                            ) +
                                        '</div>' +

                                        '<div class="muted">' +
                                            '@' +
                                            esc(
                                                employee.username
                                            ) +
                                            ' · ' +
                                            esc(
                                                employee.job_title
                                            ) +
                                        '</div>' +

                                    '</div>' +

                                '</div>' +

                            '</td>' +

                            '<td>' +
                                esc(
                                    employee.email
                                ) +
                            '</td>' +

                            '<td>' +
                                esc(
                                    employee.department_name
                                ) +
                            '</td>' +

                            '<td>' +
                                esc(
                                    employee.role_name
                                ) +
                            '</td>' +

                            '<td>' +
                                esc(
                                    employee.manager_name ||
                                    '—'
                                ) +
                            '</td>' +

                            '<td>' +

                                '<span class="badge ' +
                                    badge +
                                '">' +
                                    esc(
                                        employee.account_status
                                    ) +
                                '</span>' +

                            '</td>' +

                            '<td>' +

                                '<div class="rowActions">' +

                                    '<button class="btn small" onclick="viewEmployee(' +
                                        employee.employee_id +
                                    ')">' +
                                        'View' +
                                    '</button>' +

                                    '<button class="btn small" onclick="editEmployee(' +
                                        employee.employee_id +
                                    ')">' +
                                        'Edit' +
                                    '</button>' +

                                    '<button class="btn small danger" onclick="deactivateEmployee(' +
                                        employee.employee_id +
                                    ')">' +
                                        'Deactivate' +
                                    '</button>' +

                                '</div>' +

                            '</td>' +

                        '</tr>'

                    );

                }
            )
            .join('');

}


/* =====================================================
   ADD EMPLOYEE
===================================================== */

function openEmployeeModal() {

    editId = null;

    $('employeeForm')
        .reset();

    $('employeeModalTitle')
        .textContent =
        '/add-employee.html';

    $('saveEmployee')
        .textContent =
        'Create employee';

    $('f_password')
        .required =
        true;

    $('passwordField')
        .style
        .display =
        'flex';

    populateSelects();

    $('f_status')
        .value =
        'ACTIVE';

    $('employeeModal')
        .classList
        .add('show');

}


async function editEmployee(id) {

    try {

        var employee =
            await api(
                '/api/employees/' +
                id
            );

        editId =
            id;

        populateSelects();

        $('employeeModalTitle')
            .textContent =
            'Edit employee';

        $('saveEmployee')
            .textContent =
            'Save changes';

        $('f_password')
            .required =
            false;

        $('passwordField')
            .style
            .display =
            'none';

        $('f_username')
            .value =
            employee.username ||
            '';

        $('f_first')
            .value =
            employee.first_name ||
            '';

        $('f_last')
            .value =
            employee.last_name ||
            '';

        $('f_email')
            .value =
            employee.email ||
            '';

        $('f_phone')
            .value =
            employee.phone ||
            '';

        $('f_dob')
            .value =
            dateOnly(
                employee.date_of_birth
            );

        $('f_join')
            .value =
            dateOnly(
                employee.joining_date
            );

        $('f_dept')
            .value =
            employee.department_id;

        $('f_role')
            .value =
            employee.role_id;

        $('f_job')
            .value =
            employee.job_title ||
            '';

        $('f_manager')
            .value =
            employee.manager_id ||
            '';

        $('f_status')
            .value =
            employee.account_status ||
            'ACTIVE';

        $('f_profile')
            .value =
            '';

        $('f_resume')
            .value =
            '';

        $('employeeModal')
            .classList
            .add('show');

    } catch (error) {

        toast(
            error.message
        );

    }

}


function closeEmployeeModal() {

    $('employeeModal')
        .classList
        .remove('show');

}


/* =====================================================
   EMPLOYEE FORM
===================================================== */

$('employeeForm')
    .addEventListener(
        'submit',
        async function (event) {

            event.preventDefault();

            var payload = {

                username:
                    $('f_username')
                        .value
                        .trim(),

                first_name:
                    $('f_first')
                        .value
                        .trim(),

                last_name:
                    $('f_last')
                        .value
                        .trim(),

                email:
                    $('f_email')
                        .value
                        .trim(),

                phone:
                    $('f_phone')
                        .value
                        .trim() ||
                    null,

                date_of_birth:
                    $('f_dob')
                        .value ||
                    null,

                department_id:
                    $('f_dept')
                        .value,

                role_id:
                    $('f_role')
                        .value,

                job_title:
                    $('f_job')
                        .value
                        .trim(),

                manager_id:
                    $('f_manager')
                        .value ||
                    null,

                joining_date:
                    $('f_join')
                        .value,

                account_status:
                    $('f_status')
                        .value,

                actor_employee_id:
                    2

            };

            var currentId =
                editId;

            try {

                if (currentId) {

                    await api(
                        '/api/employees/' +
                        currentId,
                        {

                            method:
                                'PUT',

                            headers: {
                                'Content-Type':
                                    'application/json'
                            },

                            body:
                                JSON.stringify(
                                    payload
                                )

                        }
                    );

                } else {

                    payload.password =
                        $('f_password')
                            .value;

                    var created =
                        await api(
                            '/api/employees',
                            {

                                method:
                                    'POST',

                                headers: {
                                    'Content-Type':
                                        'application/json'
                                },

                                body:
                                    JSON.stringify(
                                        payload
                                    )

                            }
                        );

                    currentId =
                        created.employee_id;

                }

                var profileFile =
                    $('f_profile')
                        .files[0];

                var resumeFile =
                    $('f_resume')
                        .files[0];

                if (profileFile) {

                    await uploadFile(
                        currentId,
                        'profile',
                        profileFile
                    );

                }

                if (resumeFile) {

                    await uploadFile(
                        currentId,
                        'resume',
                        resumeFile
                    );

                }

                closeEmployeeModal();

                toast(
                    editId
                        ? 'Employee updated successfully.'
                        : 'Employee created successfully.'
                );

                await loadEmployees();

            } catch (error) {

                toast(
                    error.message
                );

            }

        }
    );


async function uploadFile(
    id,
    type,
    file
) {

    var formData =
        new FormData();

    formData.append(
        type,
        file
    );

    await api(
        '/api/employees/' +
        id +
        '/' +
        type,
        {
            method:
                'POST',

            body:
                formData
        }
    );

}


/* =====================================================
   DEACTIVATE
===================================================== */

async function deactivateEmployee(
    id
) {

    var employee =
        employees.find(
            function (item) {

                return (
                    item.employee_id ===
                    id
                );

            }
        );

    if (!employee) {
        return;
    }

    if (
        !confirm(
            'Deactivate ' +
            employee.first_name +
            ' ' +
            employee.last_name +
            '?'
        )
    ) {

        return;

    }

    try {

        await api(
            '/api/employees/' +
            id,
            {

                method:
                    'DELETE',

                headers: {
                    'Content-Type':
                        'application/json'
                },

                body:
                    JSON.stringify({
                        actor_employee_id:
                            2
                    })

            }
        );

        toast(
            'Employee deactivated.'
        );

        await loadEmployees();

    } catch (error) {

        toast(
            error.message
        );

    }

}


/* =====================================================
   EMPLOYEE DRAWER
===================================================== */

async function viewEmployee(
    id
) {

    try {

        var employee =
            await api(
                '/api/employees/' +
                id
            );

        var initials =
            (
                employee.first_name ||
                '?'
            )[0] +
            (
                employee.last_name ||
                '?'
            )[0];

        $('drawerAvatar')
            .textContent =
            initials.toUpperCase();

        $('drawerName')
            .textContent =
            employee.first_name +
            ' ' +
            employee.last_name;

        $('drawerTitle')
            .textContent =
            employee.job_title +
            ' · ' +
            employee.department_name;

        var details = [

            [
                'Employee ID',
                employee.employee_id
            ],

            [
                'Username',
                employee.username
            ],

            [
                'Email',
                employee.email
            ],

            [
                'Phone',
                employee.phone ||
                '—'
            ],

            [
                'Date of birth',
                dateOnly(
                    employee.date_of_birth
                ) ||
                '—'
            ],

            [
                'Department',
                employee.department_name
            ],

            [
                'Role',
                employee.role_name
            ],

            [
                'Manager',
                employee.manager_name ||
                '—'
            ],

            [
                'Joining date',
                dateOnly(
                    employee.joining_date
                )
            ],

            [
                'Status',
                employee.account_status
            ]

        ];

        $('drawerBody')
            .innerHTML =
            details
                .map(
                    function (item) {

                        return (

                            '<div class="detail">' +

                                '<span>' +
                                    esc(
                                        item[0]
                                    ) +
                                '</span>' +

                                '<b>' +
                                    esc(
                                        item[1]
                                    ) +
                                '</b>' +

                            '</div>'

                        );

                    }
                )
                .join('');

        var files = '';

        if (
            employee.profile_url
        ) {

            files +=

                '<div class="fileBox">' +

                    '<b>Profile picture</b>' +

                    '<br>' +

                    '<a href="' +
                        esc(
                            employee.profile_url
                        ) +
                    '" target="_blank">' +

                        'Open profile picture' +

                    '</a>' +

                '</div>';

        }

        if (
            employee.resume_url
        ) {

            files +=

                '<div class="fileBox">' +

                    '<b>Resume</b>' +

                    '<br>' +

                    '<a href="' +
                        esc(
                            employee.resume_url
                        ) +
                    '" target="_blank">' +

                        'Open resume' +

                    '</a>' +

                '</div>';

        }

        $('drawerFiles')
            .innerHTML =
            files;

        $('drawerEdit')
            .onclick =
            function () {

                closeDrawer();

                editEmployee(
                    id
                );

            };

        $('employeeDrawer')
            .classList
            .add('show');

    } catch (error) {

        toast(
            error.message
        );

    }

}


function closeDrawer() {

    $('employeeDrawer')
        .classList
        .remove('show');

}


/* =====================================================
   DEPARTMENTS
===================================================== */

function openDepartmentModal() {

    $('departmentForm')
        .reset();

    $('departmentModal')
        .classList
        .add('show');

}


function closeDepartmentModal() {

    $('departmentModal')
        .classList
        .remove('show');

}


$('departmentForm')
    .addEventListener(
        'submit',
        async function (event) {

            event.preventDefault();

            try {

                await api(
                    '/api/departments',
                    {

                        method:
                            'POST',

                        headers: {
                            'Content-Type':
                                'application/json'
                        },

                        body:
                            JSON.stringify({

                                department_name:
                                    $('d_name')
                                        .value
                                        .trim(),

                                description:
                                    $('d_desc')
                                        .value
                                        .trim()

                            })

                    }
                );

                closeDepartmentModal();

                toast(
                    'Department created.'
                );

                await loadEmployees();

                await loadDepartments();

            } catch (error) {

                toast(
                    error.message
                );

            }

        }
    );


async function loadDepartments() {

    try {

        var rows =
            await api(
                '/api/departments'
            );

        var counts = {};

        employees.forEach(
            function (employee) {

                counts[
                    employee.department_id
                ] =
                    (
                        counts[
                            employee.department_id
                        ] ||
                        0
                    ) + 1;

            }
        );

        $('departmentTable')
            .innerHTML =
            rows
                .map(
                    function (department) {

                        return (

                            '<tr>' +

                                '<td>' +
                                    department.department_id +
                                '</td>' +

                                '<td>' +

                                    '<b>' +
                                        esc(
                                            department.department_name
                                        ) +
                                    '</b>' +

                                '</td>' +

                                '<td>' +
                                    esc(
                                        department.description ||
                                        '—'
                                    ) +
                                '</td>' +

                                '<td>' +
                                    (
                                        counts[
                                            department.department_id
                                        ] ||
                                        0
                                    ) +
                                '</td>' +

                            '</tr>'

                        );

                    }
                )
                .join('');

    } catch (error) {

        toast(
            error.message
        );

    }

}


/* =====================================================
   ROLES
===================================================== */

async function loadRoles() {

    try {

        var rows =
            await api(
                '/api/role-permissions'
            );

        $('roleTable')
            .innerHTML =
            rows
                .map(
                    function (role) {

                        return (

                            '<tr>' +

                                '<td>' +

                                    '<b>' +
                                        esc(
                                            role.role_name
                                        ) +
                                    '</b>' +

                                '</td>' +

                                '<td>' +
                                    esc(
                                        role.menu
                                    ) +
                                '</td>' +

                                '<td>' +

                                    '<span class="badge">' +
                                        esc(
                                            role.action
                                        ) +
                                    '</span>' +

                                '</td>' +

                                '<td>' +
                                    esc(
                                        role.description ||
                                        ''
                                    ) +
                                '</td>' +

                            '</tr>'

                        );

                    }
                )
                .join('');

    } catch (error) {

        toast(
            error.message
        );

    }

}


/* =====================================================
   SALARY
===================================================== */

async function loadSalary() {

    try {

        var rows =
            await api(
                '/api/salaries'
            );

        $('salaryTable')
            .innerHTML =
            rows
                .map(
                    function (salary) {

                        return (

                            '<tr>' +

                                '<td>' +

                                    '<b>' +
                                        esc(
                                            salary.employee
                                        ) +
                                    '</b>' +

                                '</td>' +

                                '<td>' +
                                    money(
                                        salary.basic_salary
                                    ) +
                                '</td>' +

                                '<td>' +
                                    money(
                                        salary.allowances
                                    ) +
                                '</td>' +

                                '<td>' +
                                    money(
                                        salary.deductions
                                    ) +
                                '</td>' +

                                '<td>' +
                                    money(
                                        salary.gross_salary
                                    ) +
                                '</td>' +

                                '<td>' +

                                    '<b>' +
                                        money(
                                            salary.net_salary
                                        ) +
                                    '</b>' +

                                '</td>' +

                                '<td>' +
                                    esc(
                                        salary.currency
                                    ) +
                                '</td>' +

                                '<td>' +
                                    esc(
                                        dateOnly(
                                            salary.effective_from
                                        )
                                    ) +
                                '</td>' +

                            '</tr>'

                        );

                    }
                )
                .join('');

    } catch (error) {

        toast(
            error.message
        );

    }

}


/* =====================================================
   AUDIT
===================================================== */

async function loadAudit() {

    try {

        var rows =
            await api(
                '/api/audit-logs'
            );

        $('auditTable')
            .innerHTML =
            rows
                .map(
                    function (audit) {

                        return (

                            '<tr>' +

                                '<td>' +
                                    audit.audit_id +
                                '</td>' +

                                '<td>' +
                                    esc(
                                        audit.actor ||
                                        'System'
                                    ) +
                                '</td>' +

                                '<td>' +

                                    '<span class="badge">' +
                                        esc(
                                            audit.action
                                        ) +
                                    '</span>' +

                                '</td>' +

                                '<td>' +
                                    esc(
                                        audit.table_name
                                    ) +
                                '</td>' +

                                '<td>' +
                                    esc(
                                        audit.record_id ||
                                        '—'
                                    ) +
                                '</td>' +

                                '<td>' +
                                    esc(
                                        audit.created_at
                                    ) +
                                '</td>' +

                            '</tr>'

                        );

                    }
                )
                .join('');

    } catch (error) {

        $('auditTable')
            .innerHTML =

                '<tr>' +

                    '<td colspan="6" class="empty">' +

                        esc(
                            error.message
                        ) +

                    '</td>' +

                '</tr>';

    }

}


/* =====================================================
   REFRESH
===================================================== */

async function refreshAll() {

    await loadEmployees();

    toast(
        'Data refreshed.'
    );

}
    /* =========================================================
   CURRENT USER
========================================================= */

let currentUser = null;
let currentPermissions = [];


async function loadCurrentUser() {

    const token = localStorage.getItem('authToken');

    if (!token) {
        window.location.href = '/login';
        return;
    }

    /*
     * Immediately load cached user.
     * This prevents the UI from appearing empty
     * while /api/auth/me is loading.
     */

    try {

        const cachedUser =
            localStorage.getItem('currentUser');

        if (cachedUser) {

            currentUser =
                JSON.parse(cachedUser);

            updateCurrentUserUI();
        }

    } catch (error) {

        console.warn(
            'Could not read cached user:',
            error
        );

    }

    /*
     * Get fresh employee information.
     */

    try {

        const response = await fetch(
            '/api/auth/me',
            {
                method: 'GET',

                headers: {
                    'Authorization':
                        'Bearer ' + token
                }
            }
        );

        const data =
            await response.json();

        console.log(
            'AUTH ME:',
            response.status,
            data
        );

        if (response.ok && data.success) {

            currentUser =
                data.employee || currentUser;

            currentPermissions =
                data.permissions || [];

            localStorage.setItem(
                'currentUser',
                JSON.stringify(currentUser)
            );

            updateCurrentUserUI();

            applyPermissions();

            return;
        }

        console.warn(
            'AUTH ME failed:',
            data.message
        );

        /*
         * Keep cached login.
         * Do NOT redirect.
         */

    } catch (error) {

        console.error(
            'AUTH ME request failed:',
            error
        );

        /*
         * Keep cached login.
         * Do NOT redirect.
         */

    }
}


/* =========================================================
   UPDATE CURRENT USER UI
========================================================= */

function updateCurrentUserUI() {

    if (!currentUser) {
        return;
    }

    const firstName = currentUser.first_name || '';
    const lastName = currentUser.last_name || '';

    const fullName =
        (firstName + ' ' + lastName).trim();

    const initials =
        (
            (firstName.charAt(0) || '') +
            (lastName.charAt(0) || '')
        ).toUpperCase();

    const avatar =
        document.querySelector('.avatar');

    if (avatar) {
        avatar.textContent = initials || 'U';
    }

    const accountName =
        document.querySelector('.accountText b');

    if (accountName) {
        accountName.textContent =
            fullName || currentUser.username;
    }

    const accountRole =
        document.querySelector('.accountText small');

    if (accountRole) {
        accountRole.textContent =
            currentUser.role_name || 'Employee';
    }
}
  
function applyPermissions() {

    const role = String(
        currentUser?.role_name || ''
    ).trim().toLowerCase();
    const quickActionsPanel =
    document.getElementById('quickActionsPanel');

if (quickActionsPanel) {
    quickActionsPanel.style.display =
        role === 'employee' ? 'none' : '';

    const overviewGrid =
        quickActionsPanel.parentElement;

    if (overviewGrid) {
        overviewGrid.style.gridTemplateColumns =
            role === 'employee' ? '1fr' : '';
    }
}

    const canViewRestricted =
        role === 'hr' ||
        role === 'ceo';

    const restrictedNavIds = [
        'departmentsNav',
        'rolesNav',
        'auditNav',
        'payrollNav',
        'projectsNav'
    ];

    restrictedNavIds.forEach(function (id) {
        const element =
            document.getElementById(id);

        if (element) {
            element.style.display =
                canViewRestricted ? '' : 'none';
        }
    });

    const timesheetsNav =
        document.getElementById('timesheetsNav');

    if (timesheetsNav) {
        timesheetsNav.style.display = '';
    }
}

/* =====================================================
   INITIAL LOAD
===================================================== */

loadEmployees();
loadCurrentUser();

</script>

</body>

</html>
`;

        res.send(html);

    }
);


/* =========================================================
   LOGIN PAGE
========================================================= */

app.get('/login', function (req, res) {

    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width, initial-scale=1.0">

        <title>Company Management | Login</title>

        <style>
            * {
                box-sizing: border-box;
            }

            body {
                margin: 0;
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                font-family: Arial, sans-serif;
                background: #f1f5f9;
            }

            .login-card {
                width: 100%;
                max-width: 430px;
                padding: 40px;
                background: white;
                border-radius: 18px;
                box-shadow: 0 20px 60px rgba(0,0,0,.10);
            }

            h1 {
                margin-bottom: 8px;
                color: #0f172a;
            }

            p {
                color: #64748b;
                margin-bottom: 28px;
            }

            label {
                display: block;
                margin: 18px 0 8px;
                font-weight: 600;
                color: #334155;
            }

            input {
                width: 100%;
                padding: 14px;
                border: 1px solid #cbd5e1;
                border-radius: 9px;
                font-size: 15px;
            }

            button {
                width: 100%;
                margin-top: 25px;
                padding: 15px;
                border: none;
                border-radius: 9px;
                background: #155eef;
                color: white;
                font-size: 16px;
                font-weight: bold;
                cursor: pointer;
            }

            button:disabled {
                opacity: .6;
                cursor: not-allowed;
            }

            #message {
                margin-top: 18px;
                color: #dc2626;
                font-size: 14px;
            }
        </style>
    </head>

    <body>

        <div class="login-card">

            <h1>Welcome back</h1>
            <p>Sign in to your Company Management account.</p>

            <form id="loginForm">

                <label for="username">Username</label>
                <input
                    id="username"
                    name="username"
                    autocomplete="username"
                    required
                >

                <label for="password">Password</label>
                <input
                    id="password"
                    name="password"
                    type="password"
                    autocomplete="current-password"
                    required
                >

                <button id="loginButton" type="submit">
                    Sign in
                </button>

                <div id="message"></div>

            </form>

        </div>

        <script>
            const form = document.getElementById('loginForm');
            const message = document.getElementById('message');
            const button = document.getElementById('loginButton');

            form.addEventListener('submit', async function (event) {

                event.preventDefault();

                message.textContent = '';
                button.disabled = true;
                button.textContent = 'Signing in...';

                try {

                    const response = await fetch('/api/auth/login', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            username:
                                document.getElementById('username').value.trim(),

                            password:
                                document.getElementById('password').value
                        })
                    });

                    const data = await response.json();

                    if (!response.ok) {
                        throw new Error(
                            data.message || 'Login failed.'
                        );
                    }

                    localStorage.setItem('authToken', data.token);

localStorage.setItem(
    'currentUser',
    JSON.stringify(data.employee)
);

window.location.href = '/';

                } catch (error) {

                    message.textContent = error.message;

                } finally {

                    button.disabled = false;
                    button.textContent = 'Sign in';

                }

            });
        </script>

    </body>
    </html>
    `);

});


/* =========================================================
   LOGIN API
========================================================= */

app.post('/api/auth/login', async function (req, res) {

    try {

        const { username, password } = req.body;

        if (!username || !password) {

            return res.status(400).json({
                success: false,
                message: 'Username and password are required.'
            });

        }

        const [rows] = await pool.query(
            `
            SELECT
    employee_id,
    username,
    email,
    password_hash,
    first_name,
    last_name,
    role_id,
    department_id,
    account_status
FROM company.employees
WHERE username = ?
LIMIT 1
            `,
            [username.trim()]
        );

        if (rows.length === 0) {

            return res.status(401).json({
                success: false,
                message: 'Invalid username or password.'
            });

        }

        const employee = rows[0];

        if (
            employee.account_status !== 'ACTIVE' ||
            !verifyPassword(password, employee.password_hash)
        ) {

            return res.status(401).json({
                success: false,
                message: 'Invalid username or password.'
            });

        }

        if (!process.env.JWT_SECRET) {

            console.error('JWT_SECRET is missing from .env');

            return res.status(500).json({
                success: false,
                message: 'Authentication is not configured.'
            });

        }

        const token = jwt.sign(
            {
                employee_id: employee.employee_id,
                username: employee.username,
                role_id: employee.role_id,
                department_id: employee.department_id
            },
            process.env.JWT_SECRET,
            {
                expiresIn: '8h',
                issuer: 'company-management-api'
            }
        );

       return res.json({
    success: true,

    message: 'Login successful.',

    token: token,

    employee: {
        employee_id: employee.employee_id,
        username: employee.username,
        email: employee.email,
        first_name: employee.first_name,
        last_name: employee.last_name,
        role_id: employee.role_id,
        department_id: employee.department_id
    }
});

    } catch (error) {

        console.error('Login error:', error);

        return res.status(500).json({
            success: false,
            message: 'An internal server error occurred.'
        });

    }

});
// ==========================================
// AUTHENTICATED USER — PROFILE + PERMISSIONS
// ==========================================

app.get('/api/auth/me', async (req, res) => {

    try {

        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {

            return res.status(401).json({
                success: false,
                message: 'Please log in.'
            });

        }

        const token = authHeader.substring(7);

        if (!process.env.JWT_SECRET) {

            console.error('JWT_SECRET is missing.');

            return res.status(500).json({
                success: false,
                message: 'JWT_SECRET is not configured.'
            });

        }

        let decoded;

        try {

            decoded = jwt.verify(
                token,
                process.env.JWT_SECRET
            );

        } catch (error) {

            console.error(
                'JWT VERIFY ERROR:',
                error.message
            );

            return res.status(401).json({
                success: false,
                message: 'Session expired. Please log in again.'
            });

        }

        const employeeId = Number(decoded.employee_id);

        if (!employeeId) {

            return res.status(401).json({
                success: false,
                message: 'Invalid session.'
            });

        }

        /*
         * LOAD EMPLOYEE
         */

        const [employees] = await pool.query(
            `
            SELECT
                e.employee_id,
                e.username,
                e.first_name,
                e.last_name,
                e.email,
                e.phone,
                e.department_id,
                d.department_name,
                e.role_id,
                r.role_name,
                e.job_title,
                e.manager_id,

                CONCAT(
                    COALESCE(m.first_name, ''),
                    ' ',
                    COALESCE(m.last_name, '')
                ) AS manager_name,

                e.account_status,
                e.employee_profile_pic,
                e.employee_resume

            FROM company.employees e

            LEFT JOIN company.departments d
                ON d.department_id = e.department_id

            LEFT JOIN security.roles r
                ON r.role_id = e.role_id

            LEFT JOIN company.employees m
                ON m.employee_id = e.manager_id

            WHERE e.employee_id = ?

            LIMIT 1
            `,
            [employeeId]
        );

        if (employees.length === 0) {

            return res.status(401).json({
                success: false,
                message: 'Employee account not found.'
            });

        }

        const employee = employees[0];

        /*
         * CHECK ACCOUNT
         */

        if (employee.account_status !== 'ACTIVE') {

            return res.status(401).json({
                success: false,
                message: 'Employee account is inactive.'
            });

        }

        /*
         * LOAD PERMISSIONS
         *
         * If permissions have a problem, don't destroy
         * the authenticated session.
         */

        let permissions = [];

        try {

            const [permissionRows] = await pool.query(
                `
                SELECT
                    p.menu,
                    p.action

                FROM security.role_permissions rp

                INNER JOIN security.permissions p
                    ON p.permission_id =
                       rp.permission_id

                WHERE rp.role_id = ?

                ORDER BY
                    p.menu,
                    p.action
                `,
                [employee.role_id]
            );

            permissions = permissionRows;

        } catch (permissionError) {

            console.error(
                'PERMISSION LOAD ERROR:',
                permissionError.message
            );

            permissions = [];
        }

        /*
         * SUCCESS
         */

        return res.json({

            success: true,

            employee: employee,

            permissions: permissions

        });

    } catch (error) {

        console.error(
            'AUTH ME ERROR:',
            error
        );

        return res.status(500).json({

            success: false,

            message:
                'Could not load the current employee.'

        });

    }

});
/* =========================================================
   START SERVER
========================================================= */

// Your existing employee, department,
// timesheet and other API routes remain above.


// ========================================
// PROJECTS API ROUTES
// Paste the project API code here
// ========================================
// ==========================================
// PROJECTS API
// ==========================================

// GET ALL PROJECTS
app.get('/api/projects', async (req, res) => {
    try {
        const [projects] = await pool.query(`
            SELECT
                p.project_id,
                p.project_name,
                p.project_code,
                p.description,
                p.start_date,
                p.end_date,
                p.project_status,
                p.created_by,
                p.created_at
            FROM company.projects p
            ORDER BY p.project_id DESC
        `);

        res.json({
            success: true,
            projects: projects
        });

    } catch (error) {
        console.error('GET PROJECTS ERROR:', error);

        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});


// CREATE PROJECT
app.post('/api/projects', async (req, res) => {
    try {
        const {
            project_name,
            project_code,
            description,
            start_date,
            end_date,
            project_status,
            created_by
        } = req.body;

        if (!project_name || !project_code || !created_by) {
            return res.status(400).json({
                success: false,
                message: 'Project name, project code and creator ID are required.'
            });
        }

        const [result] = await pool.query(
            `INSERT INTO company.projects
            (
                project_name,
                project_code,
                description,
                start_date,
                end_date,
                project_status,
                created_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                project_name,
                project_code,
                description || null,
                start_date || null,
                end_date || null,
                project_status || 'PLANNED',
                created_by
            ]
        );

        res.status(201).json({
            success: true,
            message: 'Project created successfully',
            project_id: result.insertId
        });

    } catch (error) {
        console.error('CREATE PROJECT ERROR:', error);

        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});


// ==========================================
// PROJECT ASSIGNMENTS API
// ==========================================

// GET PROJECT ASSIGNMENTS
app.get('/api/project-assignments', async (req, res) => {
    try {
        const [assignments] = await pool.query(`
            SELECT
                pa.assignment_id,
                pa.project_id,
                pa.employee_id,
                pa.assigned_by,
                pa.assignment_start,
                pa.assignment_end,
                pa.allocated_hours,
                pa.assignment_status,
                p.project_name,
                p.project_code,
                e.first_name,
                e.last_name,
                e.username
            FROM company.project_assignments pa
            LEFT JOIN company.projects p
                ON pa.project_id = p.project_id
            LEFT JOIN company.employees e
                ON pa.employee_id = e.employee_id
            ORDER BY pa.assignment_id DESC
        `);

        res.json({
            success: true,
            assignments: assignments
        });

    } catch (error) {
        console.error('GET PROJECT ASSIGNMENTS ERROR:', error);

        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});
// ==========================================
// GET TIMESHEETS
// ==========================================

app.get('/api/timesheets', async (req, res) => {
    try {
        const [timesheets] = await pool.query(`
            SELECT
                t.timesheet_id,
                t.assignment_id,
                t.employee_id,
                t.work_date,
                t.hours_worked,
                t.work_description,
t.timesheet_status,

                e.first_name,
                e.last_name,
                e.username,

                p.project_name,
                p.project_code

            FROM company.timesheets t

            JOIN company.employees e
                ON e.employee_id = t.employee_id

            JOIN company.project_assignments pa
                ON pa.assignment_id = t.assignment_id

            JOIN company.projects p
                ON p.project_id = pa.project_id

            ORDER BY
                t.work_date DESC,
                t.timesheet_id DESC
        `);

        res.json(timesheets);

    } catch (error) {
        console.error('GET TIMESHEETS ERROR:', error);

        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});
/* ==========================================
   CREATE TIMESHEET
========================================== */

app.post('/api/timesheets', async (req, res) => {

    try {

        const {
            assignment_id,
            employee_id,
            work_date,
            hours_worked,
            work_description
        } = req.body;


        if (
            !assignment_id ||
            !employee_id ||
            !work_date ||
            hours_worked == null ||
            !work_description
        ) {

            return res.status(400).json({
                success: false,
                message:
                    'Assignment, employee, work date, hours and work description are required.'
            });

        }


        const hours =
            Number(hours_worked);


        if (
            !Number.isFinite(hours) ||
            hours <= 0 ||
            hours > 24
        ) {

            return res.status(400).json({
                success: false,
                message:
                    'Hours worked must be greater than 0 and no more than 24.'
            });

        }


        /*
            Make sure this employee is actually
            assigned to this project.
        */

        const [assignments] =
            await pool.query(
                `
                SELECT
                    assignment_id
                FROM company.project_assignments
                WHERE assignment_id = ?
                  AND employee_id = ?
                LIMIT 1
                `,
                [
                    Number(assignment_id),
                    Number(employee_id)
                ]
            );


        if (!assignments.length) {

            return res.status(400).json({
                success: false,
                message:
                    'This employee is not assigned to the selected project.'
            });

        }


        const [result] =
            await pool.query(
                `
             INSERT INTO company.timesheets
(
    assignment_id,
    employee_id,
    work_date,
    hours_worked,
    work_description,
    timesheet_status
)
VALUES (?, ?, ?, ?, ?, 'SUBMITTED')
                `,
                [
                    Number(assignment_id),
                    Number(employee_id),
                    work_date,
                    hours,
                    work_description
                ]
            );


        res.status(201).json({

            success: true,

            message:
                'Timesheet submitted successfully.',

            timesheet_id:
                result.insertId

        });


    } catch (error) {

        console.error(
            'CREATE TIMESHEET ERROR:',
            error
        );

        res.status(500).json({

            success: false,

            message:
                error.message

        });

    }

});


// CREATE PROJECT ASSIGNMENT
app.post('/api/project-assignments', async (req, res) => {
    try {
        const {
            project_id,
            employee_id,
            assigned_by,
            assignment_start,
            assignment_end,
            allocated_hours,
            assignment_status
        } = req.body;

        if (
            !project_id ||
            !employee_id ||
            !assigned_by ||
            !assignment_start
        ) {
            return res.status(400).json({
                success: false,
                message: 'Project, employee, assigned by and start date are required.'
            });
        }

        const [result] = await pool.query(
            `INSERT INTO company.project_assignments
            (
                project_id,
                employee_id,
                assigned_by,
                assignment_start,
                assignment_end,
                allocated_hours,
                assignment_status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                project_id,
                employee_id,
                assigned_by,
                assignment_start,
                assignment_end || null,
                allocated_hours || 0,
                assignment_status || 'ASSIGNED'
            ]
        );

        res.status(201).json({
            success: true,
            message: 'Employee assigned to project successfully',
            assignment_id: result.insertId
        });

    } catch (error) {
        console.error('CREATE ASSIGNMENT ERROR:', error);

        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// Keep this existing function unchanged
async function start() {

    try {

        const connection = await pool.getConnection();

        await connection.ping();

        connection.release();

        app.listen(
            PORT,
            function () {
                // Your existing server startup code
            }
        );

    } catch (error) {
        // Your existing error handling
    }
}
async function start() {

    try {

        const connection =
            await pool.getConnection();

        await connection.ping();

        connection.release();

        app.listen(
            PORT,
            function () {

                console.log(
                    '====================================='
                );

                console.log(
                    ' COMPANY MANAGEMENT SYSTEM'
                );

                console.log(
                    '====================================='
                );

                console.log(
                    'Website: http://localhost:' +
                    PORT
                );

                console.log(
                    'Employees API: http://localhost:' +
                    PORT +
                    '/api/employees'
                );

                console.log(
                    'Health: http://localhost:' +
                    PORT +
                    '/api/health'
                );

                console.log(
                    'MySQL: CONNECTED'
                );

                console.log(
                    'Server is ready.'
                );

            }
        );

    } catch (error) {

        console.error(
            'MySQL connection failed:',
            error.message
        );

        process.exit(1);

    }

}

start();
const users = [
    {
        name: 'Alpha',
        email: 'admin@example.com',
        password: bcrypt.hashSync('Password123', 10),
    },
];

module.exports = { users };

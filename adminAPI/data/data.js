const users = [
    {
        name: 'Alpha',
        email: 'admin@example.com',
        password: bcrypt.hashSync('12345678xD', 10),
    },
];

module.exports = { users };

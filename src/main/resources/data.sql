INSERT INTO users (enabled, password, username) VALUES (true, '$2a$12$BXeONFjoaZQfI7WH/1L0JOmrJ5oV2Q2zcVIBrLh1K3ABZG73Z9nZ6', 'admin');
INSERT INTO users (enabled, password, username) VALUES (true, '$2a$10$UIOIvN4vmO8JX7An8J.3JeWDFnUpqV7G/2m867uhLNdU3Xpu8CLVi', 'user');


INSERT INTO groups (id, group_name) VALUES (1, 'ROLE_ADMIN');
INSERT INTO groups (id, group_name) VALUES (2, 'ROLE_USER');

INSERT INTO group_members (id, username, group_id) VALUES (1, 'admin', 1);
INSERT INTO group_members (id, username, group_id) VALUES (2, 'user', 2);


INSERT INTO authorities (username, authority) VALUES ('admin', 'PERMISSION_ROUTE1');
INSERT INTO authorities (username, authority) VALUES ('admin', 'PERMISSION_ROUTE2');

INSERT INTO authorities (username, authority) VALUES ('user', 'PERMISSION_ROUTE2');
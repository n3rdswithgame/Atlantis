#ifndef AST_H
#define AST_H

namespace ast {

	enum op {
		add,
		sub,
		mul,

		ldb,
		ldh,
		ldw,

		stb,
		sth,
		stw,

		mov,
		cmp,
		b,
	};

	struct node {

	};

}//namespace ast

#endif
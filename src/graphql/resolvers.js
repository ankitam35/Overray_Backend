import schemas from "../database/schemas/index.js";
import mongoose from "mongoose";
import { GraphQLError } from "graphql";

const checkAuthentication = (context) => {
    if (!context.user)
        throw new GraphQLError(
            "You are not authorized to perform this action.",
            {
                extensions: {
                    code: "UNAUTHENTICATED",
                    http: { status: 401 },
                },
            }
        );
};

export const resolvers = {
    Query: {
        addresses: async (parent, args, contextValue) => {
            checkAuthentication(contextValue);
            return await schemas.address.find({
                user_id: contextValue.user._id,
            });
        },
        products: async (parent, args) => {
            const filter = {};
            const limit = 10;
            const start = 0;
            const sort = {};
            if (args.filter) {
                const {
                    _id,
                    categories,
                    size,
                    color,
                    minPrice,
                    maxPrice,
                    name,
                    limit: lim,
                    start: strt,
                    sort: sortOption,
                    code,
                    keywords,
                } = args.filter;

                if (_id) {
                    filter._id = new mongoose.Types.ObjectId(_id);
                }

                if (name) {
                    filter.name = { $regex: name, $options: "i" };
                }

                if (size) {
                    filter.size = size;
                }

                if (color) {
                    filter.color = color;
                }

                if (code) {
                    filter.code = code;
                }

                if (categories && categories.length > 0) {
                    filter.categories = {
                        $in: categories.map(
                            (id) => new mongoose.Types.ObjectId(id)
                        ),
                    };
                }
                if (keywords && keywords.length > 0) {
                    filter.keywords = {
                        $in: keywords,
                    };
                }

                if (minPrice !== undefined || maxPrice !== undefined) {
                    filter.price = {};

                    if (minPrice !== undefined) {
                        filter.price.$gte = minPrice;
                    }

                    if (maxPrice !== undefined) {
                        filter.price.$lte = maxPrice;
                    }
                }

                if (sortOption) {
                    sort[sortOption.field] =
                        sortOption.order === "asc" ? 1 : -1;
                }

                if (lim !== undefined) {
                    limit = lim;
                }

                if (strt !== undefined) {
                    start = strt;
                }
            }
            return await schemas.product
                .find(filter)
                .limit(limit)
                .skip(start)
                .sort(sort)
                .populate("categories")
                .populate("product_images")
                .populate({
                    path: "reviews",
                    populate: [
                        {
                            path: "user_id",
                        },
                    ],
                })
                .exec();
        },
        cart: async (parent, args, contextValue) => {
            checkAuthentication(contextValue);
            const data = await schemas.cart
                .findOne({
                    user_id: contextValue.user._id,
                })
                .populate({
                    path: "products.productId",
                    populate: [
                        { path: "categories" },
                        { path: "product_images" },
                    ],
                })
                .exec();
            return data;
        },
        wishlist: async (parent, args, contextValue) => {
            checkAuthentication(contextValue);
            const data = await schemas.wishlist
                .findOne({
                    user_id: contextValue.user._id,
                })
                .populate({
                    path: "products",
                    populate: [
                        { path: "categories" },
                        { path: "product_images" },
                    ],
                })
                .exec();
            return data;
        },
        category: async () => {
            return await schemas.category.find().exec();
        },
        banner: async () => {
            return await schemas.banner.find().exec();
        },
        lookup: async () => {
            return await schemas.lookup.find().exec();
        },
    },
    Mutation: {
        addAddress: (parent, args, contextValue) => {
            checkAuthentication(contextValue);
            const address = args.address;
            address.user_id = contextValue.user._id;
            return schemas.address.create(address);
        },
        addProductToCart: async (parent, args, contextValue) => {
            checkAuthentication(contextValue);
            const { product_id, quantity = null } = args.products;
            let cart = await schemas.cart.findOne({
                user_id: contextValue.user._id,
            });
            if (cart) {
                const existingProductIndex = cart.products.findIndex(
                    (x) => x.productId === product_id
                );
                if (existingProductIndex !== -1) {
                    cart.products[existingProductIndex].quantity += quantity;
                } else {
                    cart.products.push({
                        productId: product_id,
                        quantity: quantity,
                    });
                }
                return cart.save();
            }
            cart = new schemas.cart({
                user_id: contextValue.user._id,
                products: [
                    {
                        productId: product_id,
                        quantity: !quantity ? 1 : quantity,
                    },
                ],
            });
            return cart.save();
        },
        removeProductFromCart: async (parent, args, contextValue) => {
            checkAuthentication(contextValue);
            return schemas.cart.findOneAndUpdate(
                { user_id: contextValue.user._id },
                { $pull: { products: { productId: args.product_id } } },
                { new: true, useFindAndModify: false }
            );
        },
        addProductToWishlist: async (parent, args, contextValue) => {
            checkAuthentication(contextValue);
            let wishlist = await schemas.wishlist.findOne({
                user_id: contextValue.user._id,
            });
            if (!wishlist) {
                wishlist = new schemas.wishlist({
                    user_id: contextValue.user._id,
                    products: [args.product_id],
                });
                wishlist = await wishlist.save();
                return wishlist;
            }
            wishlist.products = [...wishlist.products, args.product_id];
            wishlist = await wishlist.save();
            return wishlist;
        },
        removeProductFromWishlist: async (parent, args, contextValue) => {
            checkAuthentication(contextValue);
            return schemas.wishlist.findOneAndUpdate(
                { user_id: contextValue.user._id },
                { $pull: { products: args.product_id } },
                { new: true, useFindAndModify: false }
            );
        },
        addProductReview: async (parent, args, contextValue) => {
            checkAuthentication(contextValue);
            const { review, score, product_id } = args.review;

            let product_review = await schemas.product_review.findOne({
                user_id: contextValue.user._id,
                product_id: product_id,
            });
            if (!product_review) {
                const newReview = new schemas.product_review({
                    user_id: contextValue.user._id,
                    product_id: product_id,
                    review: review,
                    score: score,
                });
                product_review = await newReview.save();
                return product_review;
            }
            product_review.review = review;
            product_review.score = score;
            product_review = await product_review.save();
            return product_review;
        },
    },
};

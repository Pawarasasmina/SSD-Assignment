import React from "react";
import Slider from "react-slick";
import { Link } from "react-router-dom";
import "slick-carousel/slick/slick.css";
import "slick-carousel/slick/slick-theme.css";
import "../styles/indexpage.css";

const IndexPage = () => {
  const sliderSettings = {
    dots: true,
    infinite: true,
    speed: 500,
    slidesToShow: 1,
    slidesToScroll: 1,
    autoplay: true,
    autoplaySpeed: 2000,
    arrows: true,
    pauseOnHover: true, // Pauses autoplay on hover
  };
  return (
    <div className="homepage">
      <section id="offers" className="section offers">
        <Slider {...sliderSettings} className="offer-slider">
          <div>
            <img
              src="https://img.freepik.com/free-vector/mega-sale-offers-banner-template_1017-31299.jpg?ga=GA1.1.1753345720.1723288546&semt=ais_hybrid"
              alt="50% off on Electronics"
              className="offer-image"
            />
          </div>
          <div>
            <img
              src="https://img.freepik.com/free-vector/promotion-sale-labels-best-offers_206725-127.jpg?t=st=1723357868~exp=1723361468~hmac=7d41c55863d7d1185ec051a4a054563e5ada0eead88b99cf7a4739fdc9b74cd1&w=740"
              alt="Buy 1 Get 1 Free on Fashion"
              className="offer-image"
            />
          </div>
        </Slider>
      </section>

      <section id="categories" className="section categories">
        <h2>Shop by Categories</h2>
        <div className="category-list">
          <Link to="/itemlist?category=electronics" className="category-item">
            <img
              src="https://img.freepik.com/premium-photo/gadgets-accessories-isolated-white-background_1272184-39.jpg"
              alt="Electronics"
            />
            <div>Electronics</div>
          </Link>
          <Link to="/itemlist?category=fashion" className="category-item">
            <img
              src="https://img.freepik.com/free-photo/portrait-smiling-beautiful-girl-her-handsome-boyfriend-laughing-happy-cheerful-couple-sunglasses_158538-5002.jpg?t=st=1723301802~exp=1723305402~hmac=1ca1bc78964225539b12f228a6368ad0c06948a549d391422613e1c67fc4f830&w=740"
              alt="Fashion"
            />
            <div>Fashion</div>
          </Link>
          <Link to="/itemlist?category=home-garden" className="category-item">
            <img
              src="https://img.freepik.com/premium-photo/gardening-gardener-rustic-shed-wellington-flowerpot-potted_488220-80989.jpg?ga=GA1.1.1753345720.1723288546&semt=ais_hybrid"
              alt="Home & Garden"
            />
            <div>Home & Garden</div>
          </Link>
          <Link to="/itemlist?category=health-beauty" className="category-item">
            <img
              src="https://img.freepik.com/free-vector/spa-health-beauty-template_23-2147494970.jpg?ga=GA1.1.1753345720.1723288546&semt=ais_hybrid"
              alt="Health and Beauty"
            />
            <div>Health and Beauty</div>
          </Link>
          <Link
            to="/itemlist?category=sports-outdoor"
            className="category-item"
          >
            <img
              src="https://img.freepik.com/free-photo/kettlebell-fitness-still-life_23-2151739196.jpg?ga=GA1.1.1753345720.1723288546&semt=ais_hybrid"
              alt="Sports and Outdoor"
            />
            <div>Sports and Outdoor</div>
          </Link>
          <Link to="/itemlist?category=groceries" className="category-item">
            <img
              src="https://img.freepik.com/free-photo/shopping-cart-full-with-groceries-dark-backgrounds_1268-29508.jpg?ga=GA1.1.1753345720.1723288546&semt=ais_hybrid"
              alt="Groceries"
            />
            <div>Groceries</div>
          </Link>
          <Link
            to="/itemlist?category=gaming-entertainment"
            className="category-item"
          >
            <img
              src="https://img.freepik.com/free-photo/person-wearing-futuristic-virtual-reality-glasses-gaming_23-2151133155.jpg?ga=GA1.1.1753345720.1723288546&semt=ais_hybrid"
              alt="Gaming & Entertainment"
            />
            <div>Gaming & Entertainment</div>
          </Link>
          <Link to="/itemlist?category=toys" className="category-item">
            <img
              src="https://img.freepik.com/premium-photo/toys-collection-isolated-background_488220-1015.jpg?w=740"
              alt="Toys"
            />
            <div>Toys</div>
          </Link>
        </div>
      </section>

      <section id="shops" className="section shops">
        <h2>Featured Shops</h2>
        <div className="shop-list">
          <div className="shop-item">
            <img
              src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTLr3nl3FJPy22Fwcmx1JTj4iJNCXlFFNCnLg&s"
              alt="Shop 1"
            />
            <div>Shop 1</div>
          </div>
          <div className="shop-item">
            <img
              src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSDG4VYIzWKSq1S7AmTor331LvMB61EoOCTCA&s"
              alt="Shop 2"
            />
            <div>Shop 2</div>
          </div>
          <div className="shop-item">
            <img
              src="https://www.arcadeindependencesquare.com/images/brands/titan.png"
              alt="Shop 3"
            />
            <div>Shop 3</div>
          </div>
        </div>
      </section>
    </div>
  );
};

export default IndexPage;

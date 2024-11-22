<?php
session_start();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gems Store</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <!-- Header -->
    <header class="header">
        <nav class="navbar">
            <a href="index.php" class="logo">
                <img src="image/gems_store_4-removebg-preview.png" alt="GEMS STORE Logo" style="height: 50px;">
            </a>
            <ul class="nav-links">
                <li><a href="blog.html">Blog</a></li>

                <!-- Show Admin Dashboard link only for admins -->
                <?php if (isset($_SESSION['role']) && $_SESSION['role'] === 'admin'): ?>
                    <li><a href="admin_dashboard.php">Admin Dashboard</a></li>
                <?php endif; ?>

                <!-- Show Register button if not logged in -->
                <?php if (!isset($_SESSION['username'])): ?>
                    <li><a href="register.php" class="register-btn">Register</a></li>
                <?php endif; ?>
                
                <!-- Display username with dropdown menu if logged in, otherwise show login button -->
                <?php if (isset($_SESSION['username'])): ?>
                    <li class="user-menu">
                        <a href="#" class="register-btn"><?php echo htmlspecialchars($_SESSION['username']); ?></a>
                        <div class="user-menu-content">
                            <a href="logout.php">Logout</a>
                        </div>
                    </li>
                <?php else: ?>
                    <li><a href="login.php" class="login-btn">Login</a></li>
                <?php endif; ?>
            </ul>
        </nav>
    </header>

    <!-- Banner Carousel -->
    <section class="carousel">
        <div class="carousel-container" id="carousel-container">
            <div class="carousel-slide">
                <img src="image/banner mlbb.jpg" alt="Banner 1">
            </div>
            <div class="carousel-slide">
                <img src="image/banner pubg.png" alt="Banner 2">
            </div>
            <div class="carousel-slide">
                <img src="image/genshin impact banner.jpg" alt="Banner 3">
            </div>
            <div class="carousel-slide">
                <img src="image/banner honor of kings.jpg" alt="Banner 4">
            </div>
        </div>
        <button class="carousel-prev" onclick="prevSlide()">❮</button>
        <button class="carousel-next" onclick="nextSlide()">❯</button>
    </section>

    <!-- JavaScript for Carousel Navigation -->
    <script>
        let currentSlide = 0;
        const slides = document.querySelectorAll('.carousel-slide');
        const totalSlides = slides.length;
        let slideInterval;

        function showSlide(slideIndex) {
            if (slideIndex >= totalSlides) {
                currentSlide = 0;
            } else if (slideIndex < 0) {
                currentSlide = totalSlides - 1;
            } else {
                currentSlide = slideIndex;
            }
            document.getElementById('carousel-container').style.transform = `translateX(-${currentSlide * 100}%)`;
        }

        function nextSlide() {
            showSlide(currentSlide + 1);
            resetSlideInterval();
        }

        function prevSlide() {
            showSlide(currentSlide - 1);
            resetSlideInterval();
        }

        function autoSlide() {
            slideInterval = setInterval(() => {
                showSlide(currentSlide + 1);
            }, 3000);
        }

        function resetSlideInterval() {
            clearInterval(slideInterval);
            autoSlide();
        }

        window.onload = autoSlide;
    </script>

    <!-- Instant Recharges Section -->
    <section class="recharges">
        <h2>INSTANT RECHARGES</h2>
        <div class="recharge-cards">
            <div class="card">
                <a href="mobile-legends.html">
                    <img src="image/mlbb icon.webp" alt="Mobile Legends">
                    <button><p>Mobile Legends</p></button>
                </a>
            </div>
            <div class="card">
                <a href="genshin-impact.html">
                    <img src="image/genshin impact icon.webp" alt="Genshin Impact">
                    <button><p>Genshin Impact</p></button>
                </a>
            </div>
            <div class="card">
                <a href="valorant.html">
                    <img src="image/valorant icon.webp" alt="Valorant">
                    <button><p>Valorant</p></button>
                </a>
            </div>
            <div class="card">
                <a href="honor-of-kings.html">
                    <img src="image/honor of kings icon.webp" alt="Honor Of Kings">
                    <button><p>Honor Of Kings</p></button>
                </a>
            </div>
            <div class="card">
                <a href="wild-rift.html">
                    <img src="image/wild rift icon.webp" alt="Wild Rift">
                    <button><p>Wild Rift</p></button>
                </a>
            </div>
            <div class="card">
                <a href="pubg-mobile.html">
                    <img src="image/pubg icon.webp" alt="PUBG Mobile">
                    <button><p>PUBG Mobile</p></button>
                </a>
            </div>
        </div>
    </section>

    <!-- Manual Recharges Section -->
    <section class="manual-recharges">
        <h2>MANUAL RECHARGES</h2>
        <div class="recharge-cards">
            <div class="card">
                <a href="e-football.html">
                    <img src="image/e-football icon.webp" alt="E-Football">
                    <button><p>E-Football</p></button>
                </a>
            </div>
            <div class="card">
                <a href="sausage-man.html">
                    <img src="image/sausage man icon.webp" alt="Sausage Man">
                    <button><p>Sausage Man</p></button>
                </a>
            </div>
            <div class="card">
                <a href="super-sus.html">
                    <img src="image/super sus icon.webp" alt="Super SUS">
                    <button><p>Super SUS</p></button>
                </a>
            </div>
            <div class="card">
                <a href="black-clover-m.html">
                    <img src="image/black clover m icon.webp" alt="Black Clover M">
                    <button><p>Black Clover M</p></button>
                </a>
            </div>
            <div class="card">
                <a href="clash-of-clans.html">
                    <img src="image/clash of clans icon.webp" alt="Clash of Clans">
                    <button><p>Clash of Clans</p></button>
                </a>
            </div>
            <div class="card">
                <a href="call-of-duty.html">
                    <img src="image/call of duty icon.webp" alt="Call of Duty: Mobile">
                    <button><p>Call of Duty: Mobile</p></button>
                </a>
            </div>
        </div>
    </section>

    <!-- Why Top-Up Section -->
    <section class="why-topup">
        <h2>Why top-up on Gems Store?</h2>
        <p>Thousands of gamers count on Gems Store every month for a seamless purchase experience when buying game credits or vouchers - No registration or log-in required, and purchases are added to your game account instantly. Top-up Mobile Legends, Genshin Impact, PUBG Mobile, and more now!</p>
        <div class="features">
            <div class="feature">
                <h3>Easy and Fast</h3>
                <p>It only takes a few seconds to complete a purchase on Gems Store.</p>
            </div>
            <div class="feature">
                <h3>Instant Delivery</h3>
                <p>Your purchases are delivered to your game account as soon as payment is completed.</p>
            </div>
            <div class="feature">
                <h3>Convenient Payment Methods</h3>
                <p>We partner with secured providers in Malaysia for convenience.</p>
            </div>
        </div>
    </section>

<!-- Footer -->
<footer class="footer">
    <div class="help">
        <h3>NEED HELP?</h3></div>
        <a href="https://www.whatsapp.com/" class="whatsapp-btn" target="_blank">WhatsApp</a>
    </div>
    <div class="social-media">
        <a href="https://www.facebook.com/">Facebook</a>
        <a href="https://www.instagram.com/">Instagram</a>
    </div>
    <p>© Copyright Gems Store 2024, All Rights Reserved.</p>
    <p>
        <a href="terms.html" class="terms">Terms & Conditions</a> | 
        <a href="privacy-policy.html" class="privacy-policy">Privacy Policy</a>
    </p>
</footer>
</body>
</html>

